module Blaze.UI.Types.Cfg where

import Blaze.Prelude hiding (Symbol)

import qualified Blaze.Types.Pil as Pil
import Blaze.Types.Pil (Stmt)
import Blaze.Types.Cfg ( CfNode, CfEdge, Cfg )
import qualified Blaze.Graph as G
import qualified Data.HashMap.Strict as HMap
import qualified Data.Set as Set
import Blaze.Pretty (pretty)
import Blaze.Cfg.Interprocedural (
  InterCfg,
  unInterCfg,
 )
import System.Random (Random)
import qualified Blaze.Types.Cfg as Cfg
import qualified Blaze.Types.Graph.Alga as Alga

newtype CfgId = CfgId UUID
  deriving (Eq, Ord, Show, Generic)
  deriving newtype (Random)
  deriving anyclass (Hashable, ToJSON, FromJSON)


data CfgTransport a = CfgTransport
  { edges :: [CfEdge ()]
  , root :: CfNode ()
  , nodes :: [(CfNode (), CfNode a)]
  } deriving (Eq, Ord, Show, Generic, ToJSON, FromJSON)


convertInterCfg :: InterCfg -> CfgTransport [Text]
convertInterCfg = convertPilCfg . unInterCfg

convertPilCfg :: Cfg [Stmt] -> CfgTransport [Text]
convertPilCfg pcfg = CfgTransport
  { edges =  edges'
  , root = root'
  , nodes = textNodes'
  }
  where
    root' = void $ pcfg ^. #root

    nodes' :: [(CfNode (), CfNode [Stmt])] 
    nodes' = HMap.toList $ pcfg ^. #graph . #nodeAttrMap

    textNodes' :: [(CfNode (), CfNode [Text])]
    textNodes' = fmap f nodes'
      where
        f :: (CfNode (), CfNode [Stmt]) -> (CfNode (), CfNode [Text])
        f (a, b) = (a, fmap pretty <$> b)

    edges' :: [CfEdge ()]
    edges' = fmap Cfg.fromLEdge . G.edges $ pcfg ^. #graph
