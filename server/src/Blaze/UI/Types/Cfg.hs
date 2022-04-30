module Blaze.UI.Types.Cfg where

import Blaze.UI.Prelude hiding (Symbol, group)

import qualified Blaze.Graph as G
import Blaze.Pretty (Token, mkTokenizerCtx, runTokenize, TokenizerCtx, pretty', blankTokenizerCtx)
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
import Blaze.Types.Pil.Checker (Sym(Sym), DeepSymType)
import qualified Data.HashMap.Strict as HashMap
import qualified Data.HashSet as HashSet

newtype CfgId = CfgId UUID
  deriving (Eq, Ord, Show, Generic)
  deriving newtype (Random)
  deriving anyclass (Hashable, ToJSON, FromJSON, ToJSONKey, FromJSONKey)

type TypeSymExpr = Ch.InfoExpression Ch.SymInfo
type TypeSymStmt = Pil.Statement TypeSymExpr

data TypeInfo sym pvar stype = TypeInfo
  { varSymMap :: HashMap pvar sym
  , varEqMap :: HashMap sym (HashSet sym)
  , symTypes :: HashMap sym stype
  } deriving (Generic, ToJSON, FromJSON)

type PilTypeInfo = TypeInfo Sym PilVar DeepSymType

type TokenizedTypeInfo = TypeInfo Int Symbol [Token]

data TypedCfg = TypedCfg
  { typeInfo :: PilTypeInfo
  , typeSymCfg :: GroupedCfg [TypeSymStmt]
  } deriving (Generic, ToJSON, FromJSON)

instance SqlType CfgId where
   mkLit (CfgId x) = LCustom TBlob $ Sql.mkLit x
   sqlType _ = TBlob
   fromSql x = CfgId $ Sql.fromSql x
   defaultValue = LCustom TBlob (Sql.defaultValue :: Lit UUID)

symToInt :: Sym -> Int
symToInt (Sym n) = fromIntegral n

hashMapBimap :: (Hashable k', Eq k') => (k -> k') -> (a -> a') -> HashMap k a -> HashMap k' a'
hashMapBimap f g = HashMap.fromList . fmap (bimap f g) . HashMap.toList

transportVarSymMap :: HashMap PilVar Sym -> HashMap Symbol Int
transportVarSymMap = hashMapBimap pretty' symToInt

transportVarEqMap :: HashMap Sym (HashSet Sym) -> HashMap Int (HashSet Int)
transportVarEqMap = hashMapBimap symToInt $ HashSet.map symToInt

transportSymTypes :: HashMap Sym DeepSymType -> HashMap Int [Token]
transportSymTypes = hashMapBimap symToInt tokenize
  where
    tokenize = runTokenize blankTokenizerCtx
                                            
tokenizeTypeInfo :: PilTypeInfo -> TokenizedTypeInfo
tokenizeTypeInfo t = TypeInfo
  { varSymMap = transportVarSymMap $ t ^. #varSymMap
  , varEqMap = transportVarEqMap $ t ^. #varEqMap
  , symTypes = transportSymTypes $ t ^. #symTypes
  }

untypeExpr :: TypeSymExpr -> Pil.Expression
untypeExpr x = Pil.Expression
  { size = fromIntegral $ x ^. #info . #size
  , op = fmap untypeExpr $ x ^. #op
  }

untypeStmt :: TypeSymStmt -> Pil.Stmt
untypeStmt = fmap untypeExpr

untypeCfg :: TypedCfg -> GroupedCfg [Pil.Stmt]
untypeCfg = GroupedCfg . fmap (fmap untypeStmt) . _ungroupGroupedCfg . view #typeSymCfg

tokenizeTypedCfg :: TypedCfg -> Cfg [[Token]]
tokenizeTypedCfg (TypedCfg tinfo@(TypeInfo vsMap _ _) (GroupedCfg (Cfg g rootNode nextCtxIndex))) =
  Cfg
  { graph = G.mapAttrs tokenizeNode' g
    -- TODO: This is busted if root is a group node
  , root = fmap (runTokenize tokenizerCtx) <$> rootNode
  , nextCtxIndex = nextCtxIndex
  }
  where
    tokenizerCtx = mkTokenizerCtx (Just vsMap)
    tokenizeNode' :: CfNode [TypeSymStmt] -> CfNode [[Token]]
    tokenizeNode' = tokenizeTypeSymNode tinfo tokenizerCtx

tokenizeTypeSymNode
  :: PilTypeInfo
  -> TokenizerCtx
  -> CfNode [TypeSymStmt]
  -> CfNode [[Token]]
tokenizeTypeSymNode tinfo ctx n = case n of
  Grouping gn@(GroupingNode endNode _ (Cfg _ startNode _) _) ->
    Grouping (GroupingNode
               (convert $ gn ^. #termNode)
               (gn ^. #uuid)
               -- TODO: There's no need to recurse into the inner CFG for tokenization
               --       This should be tidied up once we have `Cfg a` paramerterized
               --       on node types rather than node data types.
               (tokenizeTypedCfg . TypedCfg tinfo . GroupedCfg $ gn ^. #grouping)
               (runTokenize ctx <$> startPreview ++ [Pil.Annotation "..."] ++ endPreview))
   where
     startPreview = take 2 $ Cfg.getNodeData startNode
     endPreview = takeEnd 2 $ Cfg.getNodeData endNode
  _ -> convert n
 where
   convert = fmap $ fmap (runTokenize ctx)


----------------------
--- Grouping/Ungrouping
-- TODO: move something like this to Blaze

newtype GroupedCfg a = GroupedCfg { _ungroupGroupedCfg :: (Cfg a) }
  deriving (Generic)
  deriving newtype (ToJSON, FromJSON)

data UngroupedCfg a = UngroupedCfg
  { groupSpec :: Grp.GroupingTree a
  , cfg :: Cfg a
  } deriving (Generic, ToJSON, FromJSON)
  
ungroup :: (Hashable a, Ord a) => GroupedCfg a -> UngroupedCfg a
ungroup = uncurry (flip UngroupedCfg) . Grp.unfoldGroups . _ungroupGroupedCfg

group :: (Hashable a, Ord a) => UngroupedCfg a -> GroupedCfg a
group (UngroupedCfg spec cfg_) = GroupedCfg $ Grp.foldGroups cfg_ spec

withUngrouped :: (Cfg a -> Cfg a) -> UngroupedCfg a -> UngroupedCfg a
withUngrouped f (UngroupedCfg spec cfg_) = UngroupedCfg spec $ f cfg_

-- | Converts Grouped to Ungrouped, then regroups
asUngrouped :: (Hashable a, Ord a) => (Cfg a -> Cfg a) -> GroupedCfg a -> GroupedCfg a
asUngrouped f = group . withUngrouped f . ungroup


