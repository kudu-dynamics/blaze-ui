module Blaze.UI.Types.Graph where

import Blaze.Prelude hiding (Symbol)

import qualified Blaze.Graph as G
import Blaze.Graph (Graph)
import qualified Data.HashSet as HashSet


data GraphTransport e attr n = GraphTransport
  { edges :: [(e, (n, n))]
  , nodes :: [(n, Maybe attr)]
  } deriving (Eq, Ord, Show, Generic, ToJSON, FromJSON, Functor, Hashable)

graphToTransport :: Graph e attr n g => g -> GraphTransport e attr n
graphToTransport g = GraphTransport edges' nodes'
  where
    nodes' = fmap (\n -> (n, G.getNodeAttr n g)) . HashSet.toList . G.nodes $ g
    edges' = G.toTupleLEdge <$> G.edges g

graphFromTransport :: Graph e attr n g => GraphTransport e attr n -> g
graphFromTransport gt 
  = G.addNodesWithAttrs (mapMaybe hasAttr $ gt ^. #nodes)
  . G.addNodes (fst <$> gt ^. #nodes)
  . G.fromEdges . fmap G.fromTupleLEdge $ gt ^. #edges
  where
    hasAttr (n, Just attr) = Just (n, attr)
    hasAttr _ = Nothing
