module Blaze.UI.Cfg.Snapshot where

import Blaze.Prelude hiding (Symbol)

import Blaze.Types.Pil (Stmt)
import Blaze.Types.Cfg ( CfNode, CfEdge, Cfg )
import qualified Blaze.Graph as G
import qualified Data.HashMap.Strict as HMap
import Blaze.Pretty (pretty)
import Blaze.Cfg.Interprocedural (
  InterCfg,
  unInterCfg,
 )
import System.Random (Random)
import qualified Blaze.Types.Cfg as Cfg
import Blaze.Types.Cfg (PilCfg)
import Blaze.Function (Function)
import Blaze.UI.Types.Cfg (CfgId)
import Blaze.Types.Graph (Graph)
import qualified Blaze.Types.Graph as G
import Blaze.Types.Graph.Alga (AlgaGraph)
import Data.Time.Clock (UTCTime)
import Control.Concurrent.STM.TVar (TVar)
import Blaze.UI.Types.Cfg.Snapshot
import Blaze.UI.Types (EventLoop)

addSnapshotToBranch :: SavedCfgId -> SavedCfgId -> SnapshotInfo -> SnapshotBranch -> SnapshotBranch
addSnapshotToBranch parentId' id info snap =
  snap & #tree %~
    ( G.setNodeAttr info id
    . G.addEdge (G.LEdge () $ G.Edge parentId' id) )

renameSnapshot :: SavedCfgId -> Name -> SnapshotBranch -> SnapshotBranch
renameSnapshot id name' snap =
  snap & #tree %~ G.updateNodeAttr (over #name $ const name') id


-- handleNew :: MonadIO m => BNBinaryView -> Function -> SnapshotState -> m (Function, SnapshotState)
-- handleNew bv fn ss = do
--   mr <- liftIO $ BnCfg.getCfg (BNImporter bv) bv func
--   case mr of

-- 
updateActiveCfg :: MonadIO m
                => ActiveCfgId
                -> (PilCfg -> m PilCfg)
                -> SnapState
                -> m SnapState
updateActiveCfg = undefined

-- -- | Saves active cfg into tree of saved snapshots.
-- -- 
-- snapshotActiveCfg :: MonadIO m => ActiveCfgId -> SnapState -> m SnapState
-- snapshotActiveCfg (ActiveCfgId cid) pcfg ss = do
--   liftIO 
--   & #savedCfgs %~ HashMap.insert (SavedCfgId cid)
