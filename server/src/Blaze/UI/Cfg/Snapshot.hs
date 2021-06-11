module Blaze.UI.Cfg.Snapshot where

import Blaze.UI.Prelude hiding (Symbol)

import qualified Blaze.Graph as G
import Blaze.UI.Types.Cfg (CfgId)
import Blaze.UI.Types.Cfg.Snapshot
import qualified Blaze.UI.Types.Graph as Graph
import Blaze.UI.Types.BinaryHash (BinaryHash)
import Blaze.UI.Types.HostBinaryPath (HostBinaryPath)
import qualified Data.HashMap.Strict as HashMap

-- addSnapshotToBranch :: CfgId -> CfgId -> SnapshotInfo -> Branch BranchTree -> Branch BranchTree
-- addSnapshotToBranch parentId' id info snap =
--   snap & #tree %~ ( G.setNodeAttr info id
--        . G.addEdge (G.LEdge () $ G.Edge parentId' id) )
--        & #snapshotInfo %~

-- Adds `newChildAutoId` to tree as child of `autoId`.
addChild :: CfgId -> CfgId -> BranchTree -> BranchTree
addChild parent child = G.addEdge (G.LEdge () $ G.Edge parent child)


-- -- | Returns `Nothing` if `CfgId` is missing `SnapshotInfo`.
-- isAutosave :: CfgId -> BranchTree -> Maybe Bool
-- isAutosave cid bt = is #_Autosave . view #snapshotType <$> G.getNodeAttr cid bt

-- renameSnapshot :: CfgId -> Text -> BranchTree -> BranchTree
-- renameSnapshot id name' = G.updateNodeAttr (over #name $ const (Just name')) id

singletonBranch
  :: HostBinaryPath
  -> BinaryHash
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

