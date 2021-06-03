module Blaze.UI.Cfg.Snapshot where

import Blaze.UI.Prelude hiding (Symbol)

import qualified Blaze.Graph as G
import Blaze.UI.Types.Cfg (CfgId)
import Blaze.UI.Types.Cfg.Snapshot
import qualified Blaze.UI.Types.Graph as Graph
import Data.Time.Clock (UTCTime)
import Blaze.UI.Types.BinaryHash (BinaryHash)
import Blaze.UI.Types.HostBinaryPath (HostBinaryPath)


addSnapshotToBranch :: CfgId -> CfgId -> SnapshotInfo -> Branch BranchTree -> Branch BranchTree
addSnapshotToBranch parentId' id info snap =
  snap & #tree %~
    ( G.setNodeAttr info id
    . G.addEdge (G.LEdge () $ G.Edge parentId' id) )

-- | Changes parent snapshot type to be `Immutable` and updates time.
-- Adds `newChildAutoId` to tree as child of `autoId`.
immortalizeAutosave :: CfgId -> CfgId -> UTCTime -> BranchTree -> BranchTree
immortalizeAutosave autoId newChildAutoId saveTime bt
  = G.setNodeAttr immortalizedNodeAttr autoId
  . G.setNodeAttr newAutoNodeAttr newChildAutoId
  . G.addEdge (G.LEdge () $ G.Edge autoId newChildAutoId)
  $ bt
  where
    newAutoNodeAttr = SnapshotInfo Nothing saveTime Autosave
    immortalizedNodeAttr = case G.getNodeAttr autoId bt of
      Nothing -> SnapshotInfo Nothing saveTime Immutable
      Just x -> x & #snapshotType .~ Immutable


-- | Returns `Nothing` if `CfgId` is missing `SnapshotInfo`.
isAutosave :: CfgId -> BranchTree -> Maybe Bool
isAutosave cid bt = is #_Autosave . view #snapshotType <$> G.getNodeAttr cid bt

renameSnapshot :: CfgId -> Text -> BranchTree -> BranchTree
renameSnapshot id name' = G.updateNodeAttr (over #name $ const (Just name')) id

singletonBranch :: HostBinaryPath -> BinaryHash -> Address -> Maybe Text -> CfgId -> SnapshotInfo -> Branch BranchTree
singletonBranch hpath bhash originFuncAddr' mname rootNode' rootNodeInfo = Branch
  { hostBinaryPath = hpath
  , bndbHash = bhash
  , originFuncAddr = originFuncAddr'
  , branchName = mname
  , rootNode = rootNode'
  , tree = G.setNodeAttr rootNodeInfo rootNode'
           $ G.fromNode rootNode'
  }

toTransport :: Branch BranchTree -> Branch BranchTransport
toTransport = fmap Graph.graphToTransport

fromTransport :: Branch BranchTransport -> Branch BranchTree
fromTransport = fmap Graph.graphFromTransport

