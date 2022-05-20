module Blaze.UI.Types.Graph where

import Blaze.Prelude hiding (Symbol)

import qualified Blaze.Graph as G
import Blaze.Graph (Graph)
import qualified Data.HashSet as HashSet


data GraphTransport l n = GraphTransport
  { edges :: [(l, (n, n))]
  , nodes :: [n]
  } deriving (Eq, Ord, Show, Generic, ToJSON, FromJSON, Functor, Hashable)

graphToTransport :: Hashable n => Graph l n g => g n -> GraphTransport l n
graphToTransport g = GraphTransport edges' nodes'
  where
    nodes' = HashSet.toList . G.nodes $ g
    edges' = G.toTupleLEdge <$> G.edges g

graphFromTransport :: Graph l n g => GraphTransport l n -> g n
graphFromTransport gt 
  = G.addNodes (gt ^. #nodes)
  . G.fromEdges . fmap G.fromTupleLEdge $ gt ^. #edges
