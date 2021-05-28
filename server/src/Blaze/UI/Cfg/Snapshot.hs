module Blaze.UI.Cfg.Snapshot where

import Blaze.UI.Prelude hiding (Symbol)

import qualified Blaze.Graph as G
import Blaze.Types.Cfg (PilCfg)
import Blaze.UI.Types.Cfg (CfgId)
import Blaze.UI.Types.Cfg.Snapshot
--import Control.Concurrent.STM.TMVar (TMVar, takeTMVar, putTMVar)
import qualified Data.HashMap.Strict as HashMap
import qualified Blaze.UI.Types.Graph as Graph
import Data.Time.Clock (UTCTime)
import Blaze.UI.Types.BinaryHash (BinaryHash)

addSnapshotToBranch :: CfgId -> CfgId -> SnapshotInfo -> Branch BranchTree -> Branch BranchTree
addSnapshotToBranch parentId' id info snap =
  snap & #tree %~
    ( G.setNodeAttr info id
    . G.addEdge (G.LEdge () $ G.Edge parentId' id) )

-- | changes parent snapshot type to be Immutable and updates time.
-- Adds newAutoId to tree as child of og autoId
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


-- | Returns Nothing if CfgId is missing SnapshotInfo (which should be error)
isAutosave :: CfgId -> BranchTree -> Maybe Bool
isAutosave cid bt = is #_Autosave . view #snapshotType <$> G.getNodeAttr cid bt

renameSnapshot :: CfgId -> Text -> BranchTree -> BranchTree
renameSnapshot id name' = G.updateNodeAttr (over #name $ const (Just name')) id

singletonBranch :: BinaryHash -> Address -> Maybe Text -> CfgId -> SnapshotInfo -> Branch BranchTree
singletonBranch bhash originFuncAddr' mname rootNode' rootNodeInfo = Branch
  { bndbHash = bhash
  , originFuncAddr = originFuncAddr'
  , branchName = mname
  , rootNode = rootNode'
  , tree = G.setNodeAttr rootNodeInfo rootNode'
           $ G.fromNode rootNode'
  }

-- handleNew :: MonadIO m => BNBinaryView -> Function -> SnapshotState -> m (Function, SnapshotState)
-- handleNew bv fn ss = do
--   mr <- liftIO $ BnCfg.getCfg (BNImporter bv) bv func
--   case mr of

-- newBranchFromAutoCfg :: Address -> CfgId -> Branch
-- newBranchFromAutoCfg originFuncAddr cid =
--   Branch originFuncAddr 

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
                => CfgId
                -> (PilCfg -> m PilCfg)
                -> SnapState
                -> m (Maybe PilCfg)
updateActiveCfg cid f snap =
  case HashMap.lookup cid $ snap ^. #activeCfgs of
    Nothing -> return Nothing
    Just acfg -> fmap Just . updateTMVar f $ acfg ^. #cfg

newSavedCfgId :: MonadIO m => m CfgId
newSavedCfgId = liftIO randomIO

data SnapshotActiveCfgError = ActiveCfgNotFound CfgId
                            | SnapshotBranchNotFound BranchId
                            deriving (Eq, Ord, Show, Generic)


toTransport :: Branch BranchTree -> Branch BranchTransport
toTransport = fmap Graph.graphToTransport

fromTransport :: Branch BranchTransport -> Branch BranchTree
fromTransport = fmap Graph.graphFromTransport

-- -- | Saves active cfg into tree of saved snapshots.
-- -- returns Nothing if ActiveCfgId not found
-- snapshotActiveCfg :: MonadIO m => ActiveCfgId -> SnapState -> m (Either SnapshotActiveCfgError SnapState)
-- snapshotActiveCfg acid snap = runExceptT $ do
--   acfg <- liftMaybe (ActiveCfgNotFound acid)
--     . HashMap.lookup acid
--     $ snap ^. #activeCfgs
--   snapBranch <- liftMaybe (SnapshotBranchNotFound $ acfg ^. #branchId)
--     . HashMap.lookup (acfg ^. #branchId)
--     $ snap ^. #branches
--   cfg' <- liftIO . atomically . readTMVar $ acfg ^. #cfg
  
--     msnapBranch <- HashMap.lookup (acfg ^. #branchId) $ snap ^. #branches
--     case mSnapBranch of
--     scid <- newSavedCfgId
--     return . Just $ snap
--       & #savedCfgs %~ saveActiveCfg (acfg ^. #branchId) scid cfg'

