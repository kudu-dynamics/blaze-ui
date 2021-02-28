{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TemplateHaskell #-}

module Blaze.UI.Types.BinjaMessages where

import Blaze.Prelude hiding (Symbol)

import qualified Language.PureScript.Bridge as PB
import qualified Language.PureScript.Bridge.PSTypes as PB
import qualified Language.PureScript.Bridge.CodeGenSwitches as S
import Language.PureScript.Bridge.TypeParameters (A)
import Language.PureScript.Bridge ((^==))
import System.Directory (removeDirectoryRecursive)
import Data.BinaryAnalysis as BA
import qualified Blaze.Types.CallGraph as CG
import qualified Blaze.Types.Pil as Pil
import qualified Blaze.UI.Web.Pil as WebPil
import qualified Blaze.Types.Pil.Checker as Ch
import Blaze.Types.Cfg ( PilCfg, CfNode, BranchType )
import qualified Blaze.Graph as G
import qualified Data.HashMap.Strict as HMap
import qualified Data.Set as Set
import Blaze.Pretty (pretty)

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


