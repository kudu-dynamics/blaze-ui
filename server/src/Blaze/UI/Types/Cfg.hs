module Blaze.UI.Types.Cfg where

import Blaze.UI.Prelude hiding (TypeError, Symbol, group)

import Blaze.Pretty (Tokenizable, Token, mkTokenizerCtx, TokenizerCtx, pretty', blankTokenizerCtx, runTokenize)
import qualified Blaze.Pretty as Pretty
import Blaze.Types.Cfg (
  CfNode (
    Grouping
  ),
  Cfg (Cfg),
  GroupingNode (GroupingNode),
 )
import qualified Blaze.Cfg as Cfg
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

newtype PrintSymInfo = PrintSymInfo { _unPrintSymInfo :: Ch.SymInfo }
  deriving (Eq, Ord, Show, Generic)
  deriving anyclass (Hashable, FromJSON, ToJSON)

instance Tokenizable (Ch.InfoExpression PrintSymInfo) where
  tokenize (Ch.InfoExpression (PrintSymInfo (Ch.SymInfo bitwidth (Sym n))) op) =
    Pretty.tokenizeExprOp (Just $ Sym n) op (coerce $ bitwidth * 8)

type PrintTypeSymStmt = Pil.Statement (Ch.InfoExpression PrintSymInfo)
  
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

untypeCfg :: Cfg (CfNode [(Maybe StmtIndex, TypeSymStmt)]) -> Cfg (CfNode [Pil.Stmt])
untypeCfg = fmap $ fmap (fmap $ untypeStmt . snd)

toUnwrappedGroupedPilCfg :: TypedCfg -> Cfg (CfNode [Pil.Stmt])
toUnwrappedGroupedPilCfg = untypeCfg .  _unwrapGroupedCfg . view #typeSymCfg

untypeTypedCfg :: TypedCfg -> GroupedCfg [Pil.Stmt]
untypeTypedCfg = GroupedCfg . toUnwrappedGroupedPilCfg

tokenizeTypedCfg :: TypedCfg -> Cfg (CfNode [(Maybe StmtIndex, [Token])])
tokenizeTypedCfg (TypedCfg tinfo@(TypeInfo vsMap _ _ _) (GroupedCfg (Cfg g rootNodeId nextCtxIndex))) =
  Cfg
  { graph = tokenizeNode' <$> g
    -- TODO: This is busted if root is a group node
  , rootId = rootNodeId
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
  Grouping gn@(GroupingNode endNodeId _ innerCfg _) ->
    Grouping (GroupingNode
               endNodeId
               (gn ^. #uuid)
               -- TODO: There's no need to recurse into the inner CFG for tokenization
               --       This should be tidied up once we have `Cfg a` paramerterized
               --       on node types rather than node data types.
               (tokenizeTypedCfg . TypedCfg tinfo . GroupedCfg $ gn ^. #grouping)
               (fmap (runTokenize ctx) <$> startPreview ++ [(Nothing, Pil.Annotation "...")] ++ endPreview))
   where
     startNode = Cfg.getRootNode innerCfg
     endNode = Grp.getTermNode gn
     
     startPreview = take 2 $ Cfg.getNodeData startNode
     endPreview = takeEnd 2 $ Cfg.getNodeData endNode
  _ -> convert n
 where
   convert :: CfNode [(Maybe StmtIndex, TypeSymStmt)]
           -> CfNode [(Maybe StmtIndex, [Token])]
   convert = fmap . fmap . fmap $ runTokenize ctx . fmap (fmap PrintSymInfo)


----------------------
--- Grouping/Ungrouping
-- TODO: move something like this to Blaze

newtype GroupedCfg a = GroupedCfg { _unwrapGroupedCfg :: Cfg (CfNode a) }
  deriving (Eq, Ord, Show, Generic)
  deriving newtype (Hashable, ToJSON, FromJSON)

data UngroupedCfg a = UngroupedCfg
  { groupSpec :: Grp.GroupingTree a
  , cfg :: Cfg (CfNode a)
  } deriving (Eq, Ord, Show, Hashable, Generic, ToJSON, FromJSON)
  
ungroup :: (Hashable a, Ord a) => GroupedCfg a -> UngroupedCfg a
ungroup = uncurry (flip UngroupedCfg) . Grp.unfoldGroups . _unwrapGroupedCfg

group_ :: Hashable a => Grp.GroupingTree [a] -> Cfg (CfNode [a]) -> GroupedCfg [a]
group_ spec cfg_ = GroupedCfg $ Grp.foldGroups cfg_ spec

group :: Hashable a => UngroupedCfg [a] -> GroupedCfg [a]
group (UngroupedCfg spec cfg_) = group_ spec cfg_

withUngrouped :: (Cfg (CfNode a) -> Cfg (CfNode a)) -> UngroupedCfg a -> UngroupedCfg a
withUngrouped f (UngroupedCfg spec cfg_) = UngroupedCfg spec $ f cfg_

-- | Converts Grouped to Ungrouped, then regroups
asUngrouped :: (Hashable a, Ord a) => (Cfg (CfNode [a]) -> Cfg (CfNode [a])) -> GroupedCfg [a] -> GroupedCfg [a]
asUngrouped f = group . withUngrouped f . ungroup

