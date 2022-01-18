module Blaze.UI.Cfg.Snapshot where

import Blaze.UI.Prelude hiding (Symbol)

import qualified Blaze.Graph as G
import Blaze.UI.Types.Cfg (CfgId)
import Blaze.UI.Types.Cfg.Snapshot
import qualified Blaze.UI.Types.Graph as Graph
import Blaze.UI.Types.BndbHash (BndbHash)
import Blaze.UI.Types.HostBinaryPath (HostBinaryPath)
import qualified Data.HashMap.Strict as HashMap


-- Adds `newChildAutoId` to tree as child of `autoId`.
addChild :: CfgId -> CfgId -> BranchTree -> BranchTree
addChild parent child = G.addEdge (G.LEdge () $ G.Edge parent child)

singletonBranch
  :: HostBinaryPath
  -> BndbHash
  -> Address
  -> Text
  -> Maybe Text
  -> CfgId
  -> SnapshotInfo
  -> Branch BranchTree
singletonBranch hpath bhash originFuncAddr' originFuncName' mname rootNode' rootNodeInfo = Branch
  { hostBinaryPath = hpath
  , bndbHash = bhash
  , originFuncAddr = originFuncAddr'
  , originFuncName = originFuncName'
  , branchName = mname
  , rootNode = rootNode'
  , snapshotInfo = HashMap.fromList [(rootNode', rootNodeInfo)]
  , tree = G.fromNode rootNode'
  }

toTransport :: Branch BranchTree -> Branch BranchTransport
toTransport = fmap Graph.graphToTransport

fromTransport :: Branch BranchTransport -> Branch BranchTree
fromTransport = fmap Graph.graphFromTransport

