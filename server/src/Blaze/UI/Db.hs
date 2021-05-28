module Blaze.UI.Db
  ( module Blaze.UI.Db
  , module Exports
  ) where

import Blaze.UI.Prelude hiding ((:*:))

import qualified Prelude as P
import Blaze.UI.Types.Db as Exports
import Database.Selda
import Database.Selda.SQLite
import Blaze.UI.Types.Cfg (CfgId)
import Blaze.Types.Cfg (PilCfg)
import qualified Blaze.UI.Types.Cfg as Cfg
import Data.Time.Clock (getCurrentTime)
import qualified Blaze.UI.Types.Cfg.Snapshot as Snapshot
import Blaze.UI.Types.Cfg.Snapshot (BranchId, BranchTree, SnapshotInfo(SnapshotInfo))
import qualified Blaze.UI.Cfg.Snapshot as Snapshot
import qualified Blaze.UI.Types.Graph as Graph
import Blaze.UI.Types.BinaryHash (BinaryHash)
import Blaze.UI.Types.Graph (graphFromTransport, graphToTransport)
import Blaze.UI.Types.HostBinaryPath (HostBinaryPath)

init :: FilePath -> IO ()
init blazeSqliteFilePath = withSQLite blazeSqliteFilePath $ do
  tryCreateTable cfgTable
  tryCreateTable snapshotBranchTable

-- | Only called when creating a fresh CFG from a function
saveNewCfgAndBranch :: MonadDb m
                    => HostBinaryPath
                    -> BinaryHash
                    -> Address
                    -> PilCfg
                    -> m ( BranchId
                         , CfgId
                         , Snapshot.Branch BranchTree)
saveNewCfgAndBranch hpath bhash originFuncAddr' pcfg = do
  cid <- liftIO randomIO
  bid <- liftIO randomIO
  utc <- liftIO getCurrentTime
  saveNewCfg_ bid cid pcfg
  let b = Snapshot.singletonBranch bhash originFuncAddr' Nothing cid
          $ SnapshotInfo Nothing utc Snapshot.Autosave
  saveNewBranch_ bid hpath bhash b
  return (bid, cid, b)
    

-- | use `saveNewCfgAndBranch` instead
saveNewCfg_ :: MonadDb m => BranchId -> CfgId -> PilCfg -> m ()
saveNewCfg_ bid cid cfg' = withDb $ do
  insert_ cfgTable
    [ SavedCfg cid bid . Blob $ Cfg.toTransport identity cfg' ]

setCfgName :: MonadDb m => BranchId -> CfgId -> Text -> m ()
setCfgName bid cid name' = modifyBranchTree bid
  $ Snapshot.renameSnapshot cid name'  


setCfg :: MonadDb m => CfgId -> PilCfg -> m ()
setCfg cid pcfg = withDb $ do
  -- utc <- liftIO getCurrentTime
  update_ cfgTable
    (\immCfg -> immCfg ! #cfgId .== literal cid)
    (\immCfg -> immCfg `with` [ #cfg := literal (Blob $ Cfg.toTransport identity pcfg)
                              -- , #modified := literal utc
                              ])

getSavedCfg :: MonadDb m => CfgId -> m [SavedCfg]
getSavedCfg cid = withDb $ do
  query $ do
    cfg' <- select cfgTable
    restrict (cfg' ! #cfgId .== literal cid)
    return $ cfg'

getCfg :: MonadDb m => CfgId -> m (Maybe PilCfg)
getCfg cid = (fmap $ view #cfg) <$> getSavedCfg cid >>= \case
  [] -> return Nothing
  [Blob x] -> return . Just . Cfg.fromTransport $ x
  _ -> -- hopefully impossible
    P.error $ "PRIMARY KEY apparently not UNIQUE for id: " <> show cid

getCfgBinaryHash :: MonadDb m => CfgId -> m (Maybe BinaryHash)
getCfgBinaryHash cid = withDb $ do
  xs <- query $ do
    cfg' <- select cfgTable
    restrict (cfg' ! #cfgId .== literal cid)
    branch <- select snapshotBranchTable
    restrict (branch ! #branchId .== cfg' ! #branchId)
    return $ branch ! #bndbHash
  case xs of
    [] -> return Nothing
    [h] -> return $ Just h
    _ -> P.error "getCfgBinaryHash: returned multiple branch ids"

getCfgBranchId :: MonadDb m => CfgId -> m (Maybe BranchId)
getCfgBranchId cid = withDb $ do
  xs <- query $ do
    cfg' <- select cfgTable
    restrict (cfg' ! #cfgId .== literal cid)
    return $ cfg' ! #branchId
  case xs of
    [] -> return Nothing
    [h] -> return $ Just h
    _ -> P.error "getCfgBranchId: returned multiple branch ids"

  

-- | use `saveNewCfgAndBranch`
saveNewBranch_ :: MonadDb m
  => BranchId
  -> HostBinaryPath
  -> BinaryHash
  -> Snapshot.Branch BranchTree
  -> m ()
saveNewBranch_ bid hpath h b = withDb $
  insert_ snapshotBranchTable
    [ SnapshotBranch
      bid
      hpath
      h
      (b ^. #originFuncAddr)
      (b ^. #branchName)
      (b ^. #rootNode)
      . Blob
      . Graph.graphToTransport
      $ b ^. #tree
    ]


setBranchTree :: MonadDb m => BranchId -> BranchTree -> m ()
setBranchTree bid branchTree = withDb $ do
  update_ snapshotBranchTable
    (\b -> b ! #branchId .== literal bid)
    (\b -> b `with` [ #tree := literal (Blob . graphToTransport $ branchTree)])

setBranchName :: MonadDb m => BranchId -> Maybe Text -> m ()
setBranchName bid mname = withDb $ do
  update_ snapshotBranchTable
    (\b -> b ! #branchId .== literal bid)
    (\b -> b `with` [ #branchName := literal mname ])


getBranch :: MonadDb m => BranchId -> m (Maybe (Snapshot.Branch BranchTree))
getBranch bid = withDb $ do
  xs <- query $ do
    branch <- select snapshotBranchTable
    restrict (branch ! #branchId .== literal bid)
    return branch
  case xs of
    [] -> return Nothing
    [SnapshotBranch _ _ bhash originFuncAddr' mname rootNode' (Blob tree')] -> return
      . Just 
      . Snapshot.Branch bhash originFuncAddr' mname rootNode'
      . graphFromTransport
      $ tree'
    _ -> -- hopefully impossible
      P.error $ "PRIMARY KEY apparently not UNIQUE for id: " <> show bid

-- TODO: Add a lock so branch can't be opened while being modified
-- or make some abstraction were you just modify tvars and it updates the db
-- automatically
modifyBranchTree :: MonadDb m => BranchId -> (BranchTree -> BranchTree) -> m ()
modifyBranchTree bid f = getBranch bid >>= \case
  Nothing -> return ()
  Just b -> setBranchTree bid (f $ b ^. #tree)

getBranchesForFunction :: MonadDb m => HostBinaryPath -> Address -> m [(BranchId, Snapshot.Branch BranchTree)]
getBranchesForFunction hpath funcAddr = fmap (fmap f) . withDb . query $ do
  branch <- select snapshotBranchTable
  restrict (branch ! #originFuncAddr .== literal funcAddr
            .&& branch ! #hostBinaryPath .== literal hpath)
  return branch
  where
    f :: SnapshotBranch -> (BranchId, Snapshot.Branch BranchTree)
    f (SnapshotBranch bid _ bhash faddr mname root (Blob tree')) =
      ( bid
      , Snapshot.Branch bhash faddr mname root $ graphFromTransport tree'
      )

getAllBranches :: MonadDb m => HostBinaryPath -> m [(BranchId, Snapshot.Branch BranchTree)]
getAllBranches hpath = fmap (fmap f) . withDb . query $ do
  branch <- select snapshotBranchTable
  restrict (branch ! #hostBinaryPath .== literal hpath)
  return branch
  where
    f :: SnapshotBranch -> (BranchId, Snapshot.Branch BranchTree)
    f (SnapshotBranch bid _ bhash faddr mname root (Blob tree')) =
      ( bid
      , Snapshot.Branch bhash faddr mname root $ graphFromTransport tree'
      )

