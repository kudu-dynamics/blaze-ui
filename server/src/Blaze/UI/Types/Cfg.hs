module Blaze.UI.Types.Cfg where

import Blaze.UI.Prelude hiding (TypeError, Symbol, group)

import qualified Blaze.Graph as G
import Blaze.Pretty (Tokenizable, Token, mkTokenizerCtx, runTokenize, TokenizerCtx, pretty', blankTokenizerCtx)
import Blaze.Types.Cfg (
  CfNode (
    Grouping
  ),
  Cfg (Cfg),
  GroupingNode (GroupingNode),
 )
import qualified Blaze.Types.Cfg as Cfg
import qualified Blaze.Types.Cfg.Grouping as Grp
import Data.List.Extra (takeEnd)
import System.Random (Random)
import Database.Selda.SqlType ( Lit(LCustom)
                              , SqlTypeRep(TBlob)
                              , SqlType
                              )
import qualified Database.Selda.SqlType as Sql
import qualified Blaze.Types.Pil as Pil
import Blaze.Types.Pil (PilVar, Symbol)
import qualified Blaze.Types.Pil.Checker as Ch
import Blaze.Types.Pil.Checker (Sym(Sym), DeepSymType, TypeReport, UnifyConstraintsError)
import qualified Data.HashMap.Strict as HashMap


type StmtIndex = Int

newtype CfgId = CfgId UUID
  deriving (Eq, Ord, Show, Generic)
  deriving newtype (Random)
  deriving anyclass (Hashable, ToJSON, FromJSON, ToJSONKey, FromJSONKey)

type TypeSymExpr = Ch.InfoExpression Ch.SymInfo
type TypeSymStmt = Pil.Statement TypeSymExpr

data TypeError = TypeError
  { stmtOrigin :: Int -- ^ Index in list of pil stmts for now
  , sym :: Sym
  , error :: [Token]
  }
  deriving (Eq, Ord, Show, Generic, Hashable, FromJSON, ToJSON)  

data TypeInfo pvar stype err = TypeInfo
  { varSymMap :: HashMap pvar Sym
  , varEqMap :: HashMap Sym (HashSet Sym)
  , symTypes :: HashMap Sym stype
  , typeErrors :: [err]
  } deriving (Eq, Ord, Show, Hashable, Generic, ToJSON, FromJSON)

type TokenizedTypeInfo = TypeInfo Symbol [Token] TypeError

type PilTypeInfo = TypeInfo PilVar DeepSymType (UnifyConstraintsError DeepSymType)

typeInfoFromTypeReport :: TypeReport -> PilTypeInfo
typeInfoFromTypeReport tr = TypeInfo
  { varSymMap = tr ^. #varSymMap
  , varEqMap = tr ^. #varEqMap
  , symTypes = tr ^. #solutions
  , typeErrors = tr ^. #errors
  }

data TypedCfg = TypedCfg
  { typeInfo :: PilTypeInfo
  , typeSymCfg :: GroupedCfg [(Maybe StmtIndex, TypeSymStmt)]
  } deriving (Eq, Ord, Show, Hashable, Generic, ToJSON, FromJSON)

instance SqlType CfgId where
   mkLit (CfgId x) = LCustom TBlob $ Sql.mkLit x
   sqlType _ = TBlob
   fromSql x = CfgId $ Sql.fromSql x
   defaultValue = LCustom TBlob (Sql.defaultValue :: Lit UUID)

symToInt :: Sym -> Int
symToInt (Sym n) = fromIntegral n

hashMapBimap :: (Hashable k', Eq k') => (k -> k') -> (a -> a') -> HashMap k a -> HashMap k' a'
hashMapBimap f g = HashMap.fromList . fmap (bimap f g) . HashMap.toList

transportVarSymMap :: HashMap PilVar Sym -> HashMap Symbol Sym
transportVarSymMap = HashMap.mapKeys pretty'

transportSymTypes :: HashMap Sym DeepSymType -> HashMap Sym [Token]
transportSymTypes = HashMap.map tokenize

tokenize :: Tokenizable a => a -> [Token]
tokenize = runTokenize blankTokenizerCtx

tokenizeTypeInfo :: PilTypeInfo -> TokenizedTypeInfo
tokenizeTypeInfo t = TypeInfo
  { varSymMap = transportVarSymMap $ t ^. #varSymMap
  , varEqMap = t ^. #varEqMap
  , symTypes = transportSymTypes $ t ^. #symTypes
  , typeErrors = tokenizeTypeError <$> t ^. #typeErrors
  }

tokenizeTypeError :: UnifyConstraintsError DeepSymType -> TypeError
tokenizeTypeError u = TypeError
  { stmtOrigin = u ^. #stmtOrigin
  , sym = u ^. #sym
  , error = tokenize $ u ^. #error
  }

untypeExpr :: TypeSymExpr -> Pil.Expression
untypeExpr x = Pil.Expression
  { size = fromIntegral $ x ^. #info . #size
  , op = fmap untypeExpr $ x ^. #op
  }

untypeStmt :: TypeSymStmt -> Pil.Stmt
untypeStmt = fmap untypeExpr

untypeCfg :: Cfg [(Maybe StmtIndex, TypeSymStmt)] -> Cfg [Pil.Stmt]
untypeCfg = fmap (fmap $ untypeStmt . snd)

toUnwrappedGroupedPilCfg :: TypedCfg -> Cfg [Pil.Stmt]
toUnwrappedGroupedPilCfg = untypeCfg .  _unwrapGroupedCfg . view #typeSymCfg

untypeTypedCfg :: TypedCfg -> GroupedCfg [Pil.Stmt]
untypeTypedCfg = GroupedCfg . toUnwrappedGroupedPilCfg

tokenizeTypedCfg :: TypedCfg -> Cfg [(Maybe StmtIndex, [Token])]
tokenizeTypedCfg (TypedCfg tinfo@(TypeInfo vsMap _ _ _) (GroupedCfg (Cfg g rootNode nextCtxIndex))) =
  Cfg
  { graph = G.mapAttrs tokenizeNode' g
    -- TODO: This is busted if root is a group node
  , root = tokenizeNode' rootNode
  , nextCtxIndex = nextCtxIndex
  }
  where
    tokenizerCtx = mkTokenizerCtx (Just vsMap)
    tokenizeNode' :: CfNode [(Maybe StmtIndex, TypeSymStmt)] -> CfNode [(Maybe StmtIndex, [Token])]
    tokenizeNode' = tokenizeTypeSymNode tinfo tokenizerCtx

tokenizeTypeSymNode
  :: PilTypeInfo
  -> TokenizerCtx
  -> CfNode [(Maybe StmtIndex, TypeSymStmt)]
  -> CfNode [(Maybe StmtIndex, [Token])]
tokenizeTypeSymNode tinfo ctx n = case n of
  Grouping gn@(GroupingNode endNode _ (Cfg _ startNode _) _) ->
    Grouping (GroupingNode
               (convert $ gn ^. #termNode)
               (gn ^. #uuid)
               -- TODO: There's no need to recurse into the inner CFG for tokenization
               --       This should be tidied up once we have `Cfg a` paramerterized
               --       on node types rather than node data types.
               (tokenizeTypedCfg . TypedCfg tinfo . GroupedCfg $ gn ^. #grouping)
               (fmap (runTokenize ctx) <$> startPreview ++ [(Nothing, Pil.Annotation "...")] ++ endPreview))
   where
     startPreview = take 2 $ Cfg.getNodeData startNode
     endPreview = takeEnd 2 $ Cfg.getNodeData endNode
  _ -> convert n
 where
   convert :: CfNode [(Maybe StmtIndex, TypeSymStmt)]
           -> CfNode [(Maybe StmtIndex, [Token])]
   convert = fmap . fmap . fmap $ runTokenize ctx -- fmaps: node => list => tuple


----------------------
--- Grouping/Ungrouping
-- TODO: move something like this to Blaze

newtype GroupedCfg a = GroupedCfg { _unwrapGroupedCfg :: Cfg a }
  deriving (Eq, Ord, Show, Generic)
  deriving newtype (Hashable, ToJSON, FromJSON)

data UngroupedCfg a = UngroupedCfg
  { groupSpec :: Grp.GroupingTree a
  , cfg :: Cfg a
  } deriving (Eq, Ord, Show, Hashable, Generic, ToJSON, FromJSON)
  
ungroup :: (Hashable a, Ord a) => GroupedCfg a -> UngroupedCfg a
ungroup = uncurry (flip UngroupedCfg) . Grp.unfoldGroups . _unwrapGroupedCfg

group_ :: (Hashable a, Ord a) => Grp.GroupingTree a -> Cfg a -> GroupedCfg a
group_ spec cfg_ = GroupedCfg $ Grp.foldGroups cfg_ spec

group :: (Hashable a, Ord a) => UngroupedCfg a -> GroupedCfg a
group (UngroupedCfg spec cfg_) = group_ spec cfg_

withUngrouped :: (Cfg a -> Cfg a) -> UngroupedCfg a -> UngroupedCfg a
withUngrouped f (UngroupedCfg spec cfg_) = UngroupedCfg spec $ f cfg_

-- | Converts Grouped to Ungrouped, then regroups
asUngrouped :: (Hashable a, Ord a) => (Cfg a -> Cfg a) -> GroupedCfg a -> GroupedCfg a
asUngrouped f = group . withUngrouped f . ungroup


