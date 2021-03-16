{-# LANGUAGE DataKinds #-}

module Blaze.UI.Types.BinjaMessages where

import Blaze.Prelude hiding (Symbol)

import qualified Blaze.Types.Pil as Pil
import Blaze.Types.Cfg ( PilCfg, CfNode, BranchType )
import qualified Blaze.Graph as G
import qualified Data.HashMap.Strict as HMap
import qualified Data.Set as Set
import Blaze.Pretty (pretty)
import Blaze.Cfg.Interprocedural (
  InterCfg,
  unInterCfg,
 )

type CfgId = UUID

convertInterCfg :: InterCfg -> Cfg (CfNode [Text])
convertInterCfg = convertPilCfg . unInterCfg

convertPilCfg :: PilCfg -> Cfg (CfNode [Text])
convertPilCfg pcfg = Cfg
  { edges =  edges'
  , root = root'
  , nodeMap = intNodeMapping'
  }
  where
    nodeList :: [CfNode [Pil.Stmt]]
    nodeList = Set.toList . G.nodes $ pcfg ^. #graph

    intNodeMapping :: [(Int, CfNode [Pil.Stmt])]
    intNodeMapping = zip [0..] nodeList

    -- temporary, just sending text instead of a stmt data type
    intNodeMapping' :: [(Int, CfNode [Text])]
    intNodeMapping' = fmap f intNodeMapping
      where
        f (id, node) = (id, fmap pretty <$> node)

    nodeIntMap :: HashMap (CfNode [Pil.Stmt]) Int
    nodeIntMap = HMap.fromList $ zip nodeList [0..]

    root' = getNodeId (pcfg ^. #root)

    getNodeId node = fromJust $ HMap.lookup node nodeIntMap
  
    edges' = fmap (\(e, (a, b)) ->
                     CfEdge (getNodeId a) (getNodeId b) e
                  )
             . G.edges
             $ pcfg ^. #graph

data CfEdge a = CfEdge
  { src :: a
  , dst :: a
  , branchType :: BranchType
  } deriving (Eq, Ord, Show, Generic, ToJSON, FromJSON)

data Cfg a = Cfg
  { edges :: [CfEdge Int]
  , root :: Int
  , nodeMap :: [(Int, a)]
  } deriving (Eq, Ord, Show, Generic, ToJSON, FromJSON)


