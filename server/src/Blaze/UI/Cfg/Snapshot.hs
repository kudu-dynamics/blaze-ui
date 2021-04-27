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
import Control.Concurrent.STM.TMVar (TMVar, takeTMVar, putTMVar, readTMVar)
import qualified Data.HashMap.Strict as HashMap

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

-- | locks TMVar while performing some effectual operation on contents
updateTMVar :: MonadIO m => (a -> m a) -> TMVar a -> m a
updateTMVar f v = do
  x <- liftIO . atomically $ takeTMVar v
  x' <- f x
  liftIO . atomically $ putTMVar v x'
  return x'

-- | Mutates active cfg (in TMVvar) if it can be found.
-- returns modified cfg
updateActiveCfg :: MonadIO m
                => ActiveCfgId
                -> (PilCfg -> m PilCfg)
                -> SnapState
                -> m (Maybe PilCfg)
updateActiveCfg cid f snap =
  case HashMap.lookup cid $ snap ^. #activeCfgs of
    Nothing -> return Nothing
    Just acfg -> fmap Just . updateTMVar f $ acfg ^. #cfg

newSavedCfgId :: MonadIO m => m SavedCfgId
newSavedCfgId = liftIO randomIO

data SnapshotActiveCfgError = ActiveCfgNotFound ActiveCfgId
                            | SnapshotBranchNotFound BranchId
                            deriving (Eq, Ord, Show, Generic)

-- | Saves active cfg into tree of saved snapshots.
-- returns Nothing if ActiveCfgId not found
snapshotActiveCfg :: MonadIO m => ActiveCfgId -> SnapState -> m (Either SnapshotActiveCfgError SnapState)
snapshotActiveCfg acid snap = runExceptT $ do
  acfg <- liftMaybe (ActiveCfgNotFound acid)
    . HashMap.lookup acid
    $ snap ^. #activeCfgs
  snapBranch <- liftMaybe (SnapshotBranchNotFound $ acfg ^. #branchId)
    . HashMap.lookup (acfg ^. #branchId)
    $ snap ^. #branches
  cfg' <- liftIO . atomically . readTMVar $ acfg ^. #cfg
  
    msnapBranch <- HashMap.lookup (acfg ^. #branchId) $ snap ^. #branches
    case mSnapBranch of
    scid <- newSavedCfgId
    return . Just $ snap
      & #savedCfgs %~ saveActiveCfg (acfg ^. #branchId) scid cfg'

