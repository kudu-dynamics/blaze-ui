module Blaze.UI.Types.Cfg where

import Blaze.UI.Prelude hiding (Symbol)

import qualified Blaze.Graph as G
import Blaze.Pretty (Token, mkTokenizerCtx, runTokenize, TokenizerCtx)
import Blaze.Types.Cfg.Grouping (
  CfNode (
    Grouping
  ),
  Cfg (Cfg),
  GroupingNode (GroupingNode),
 )
import qualified Blaze.Types.Cfg.Grouping as Cfg
import Data.List.Extra (takeEnd)
import System.Random (Random)
import Database.Selda.SqlType ( Lit(LCustom)
                              , SqlTypeRep(TBlob)
                              , SqlType
                              )
import qualified Database.Selda.SqlType as Sql
import qualified Blaze.Types.Pil as Pil
import qualified Blaze.Types.Pil.Checker as Ch
import Blaze.Types.Pil.Checker (Sym, DeepSymType, VarEqMap, VarSymMap)


newtype CfgId = CfgId UUID
  deriving (Eq, Ord, Show, Generic)
  deriving newtype (Random)
  deriving anyclass (Hashable, ToJSON, FromJSON, ToJSONKey, FromJSONKey)

type TypeSymExpr = Ch.InfoExpression Ch.SymInfo
type TypeSymStmt = Pil.Statement TypeSymExpr

data TypeInfo = TypeInfo
  { varSymMap :: VarSymMap
  , varEqMap :: VarEqMap
  , symTypes :: HashMap Sym DeepSymType
  } deriving (Generic, ToJSON, FromJSON)

data TypeSymCfg = TypeSymCfg
  { typeInfo :: TypeInfo
  , cfg :: Cfg [TypeSymStmt]
  } deriving (Generic, ToJSON, FromJSON)


instance SqlType CfgId where
   mkLit (CfgId x) = LCustom TBlob $ Sql.mkLit x
   sqlType _ = TBlob
   fromSql x = CfgId $ Sql.fromSql x
   defaultValue = LCustom TBlob (Sql.defaultValue :: Lit UUID)

tokenizeTypeSymCfg :: TypeSymCfg -> Cfg [[Token]]
tokenizeTypeSymCfg (TypeSymCfg tinfo@(TypeInfo vsMap _ _) (Cfg g rootNode nextCtxIndex)) =
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
  :: TypeInfo
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
               (tokenizeTypeSymCfg . TypeSymCfg tinfo $ gn ^. #grouping)
               (runTokenize ctx <$> startPreview ++ [Pil.Annotation "..."] ++ endPreview))
   where
     startPreview = take 2 $ Cfg.getNodeData startNode
     endPreview = takeEnd 2 $ Cfg.getNodeData endNode
  _ -> convert n
 where
   convert = fmap $ fmap (runTokenize ctx)

