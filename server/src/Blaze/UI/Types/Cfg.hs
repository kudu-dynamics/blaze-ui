module Blaze.UI.Types.Cfg where

import Blaze.UI.Prelude hiding (Symbol)

import qualified Blaze.Graph as G
import Blaze.Pretty (Token, mkTokenizerCtx, runTokenize, TokenizerCtx)
import Blaze.Types.Cfg.Grouping (
  CfEdge (CfEdge),
  CfNode (
    Grouping
  ),
  Cfg (Cfg),
  GroupingNode (GroupingNode),
  PilCfg,
 )
import qualified Blaze.Types.Cfg.Grouping as Cfg
import Blaze.Types.Pil (Stmt)
import qualified Data.HashMap.Strict as HashMap
import Database.Selda.SqlType (
  Lit (LCustom),
  SqlType,
  SqlTypeRep (TBlob),
 )
import Data.List.Extra (takeEnd)
import qualified Database.Selda.SqlType as Sql
import System.Random (Random)
import qualified Blaze.Types.Pil as Pil
newtype CfgId = CfgId UUID
  deriving (Eq, Ord, Show, Generic)
  deriving newtype (Random)
  deriving anyclass (Hashable, ToJSON, FromJSON, ToJSONKey, FromJSONKey)

instance SqlType CfgId where
   mkLit (CfgId x) = LCustom TBlob $ Sql.mkLit x
   sqlType _ = TBlob
   fromSql x = CfgId $ Sql.fromSql x
   defaultValue = LCustom TBlob (Sql.defaultValue :: Lit UUID)

data CfgTransport a = CfgTransport
  { edges :: [CfEdge ()]
  , root :: CfNode ()
  , nodes :: [(CfNode (), CfNode a)]
  } deriving (Eq, Ord, Show, Generic, ToJSON, FromJSON, Functor)

-- convertInterCfg :: InterCfg -> CfgTransport [[Token]]
-- convertInterCfg = convertPilCfg . unInterCfg

convertPilCfg :: PilCfg -> Cfg [[Token]]
convertPilCfg cfg@(Cfg g rootNode) =
  Cfg
  { graph = G.mapAttrs tokenizeNode' g
    -- TODO: This is busted if root is a group node
  , root = fmap (runTokenize tokenizerCtx) <$> rootNode
  }
  where
    tokenizerCtx = mkTokenizerCtx (fst $ Cfg.unfoldGroups cfg)
    tokenizeNode' :: CfNode [Stmt] -> CfNode [[Token]]
    tokenizeNode' = tokenizeNode tokenizerCtx

tokenizeNode :: TokenizerCtx -> CfNode [Stmt] -> CfNode [[Token]]
tokenizeNode ctx n = case n of
  Grouping gn@(GroupingNode endNode _ (Cfg _ startNode) _) ->
    Grouping (GroupingNode
               (convert $ gn ^. #termNode)
               (gn ^. #uuid)
               -- TODO: There's no need to recurse into the inner CFG for tokenization
               --       This should be tidied up once we have `Cfg a` paramerterized
               --       on node types rather than node data types.
               (convertPilCfg $ gn ^. #grouping)
               (runTokenize ctx <$> startPreview ++ [Pil.Annotation "..."] ++ endPreview))
   where
     startPreview = take 2 $ Cfg.getNodeData startNode
     endPreview = takeEnd 2 $ Cfg.getNodeData endNode
  _ -> convert n
 where
   convert = fmap $ fmap (runTokenize ctx)

toTransport :: forall a b. (a -> b) -> Cfg a -> CfgTransport b
toTransport f pcfg = CfgTransport
  { edges =  edges'
  , root = root'
  , nodes = textNodes'
  }
  where
    root' = void $ pcfg ^. #root

    nodes' :: [(CfNode (), CfNode a)]
    nodes' = HashMap.toList $ pcfg ^. #graph . #nodeAttrMap

    textNodes' :: [(CfNode (), CfNode b)]
    textNodes' = fmap g nodes'
      where
        g :: (CfNode (), CfNode a) -> (CfNode (), CfNode b)
        g (a, b) = (a, f <$> b)

    edges' :: [CfEdge ()]
    edges' = fmap Cfg.fromLEdge . G.edges $ pcfg ^. #graph


fromTransport :: (Eq a, Hashable a) => CfgTransport a -> Cfg a
fromTransport t = Cfg.mkCfg root' nodes' edges'
  where
    nodeMap = HashMap.fromList $ t ^. #nodes

    fullNode = fromJust . flip HashMap.lookup nodeMap

    fullEdge e = CfEdge
      { src = fullNode $ e ^. #src
      , dst = fullNode $ e ^. #dst
      , branchType = e ^. #branchType
      }

    root' = fullNode $ t ^. #root

    nodes' = snd <$> t ^. #nodes

    edges' = fullEdge <$> t ^. #edges
