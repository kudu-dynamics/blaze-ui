module Blaze.UI.Db
  ( module Blaze.UI.Db
  , module Exports
  ) where

import Blaze.UI.Prelude hiding ((:*:))

import qualified Prelude as P
import Blaze.UI.Types.Db as Exports hiding (cfg)
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
import Blaze.UI.Types.Session (ClientId)
import qualified Data.HashMap.Strict as HashMap

init :: FilePath -> IO ()
init blazeSqliteFilePath = withSQLite blazeSqliteFilePath $ do
  tryCreateTable cfgTable
  tryCreateTable snapshotBranchTable

-- | Only called when creating a fresh CFG from a function
saveNewCfgAndBranch :: MonadDb m
                    => ClientId
                    -> HostBinaryPath
                    -> BinaryHash
                    -> Address
                    -> Text
                    -> PilCfg
                    -> m ( BranchId
                         , CfgId
                         , Snapshot.Branch BranchTree)
saveNewCfgAndBranch clientId' hpath bhash originFuncAddr' originFuncName' pcfg = do
  cid <- liftIO randomIO
  bid <- liftIO randomIO
  utc <- liftIO getCurrentTime
  saveNewCfg_ bid cid pcfg
  let b = Snapshot.singletonBranch hpath bhash originFuncAddr' originFuncName' Nothing cid
          $ SnapshotInfo Nothing utc Snapshot.Autosave
  saveNewBranch_ bid clientId' hpath bhash b
  return (bid, cid, b)

-- | use `saveNewCfgAndBranch` instead
saveNewCfg_ :: MonadDb m => BranchId -> CfgId -> PilCfg -> m ()
saveNewCfg_ bid cid cfg = withDb $ do
  insert_ cfgTable
    [ SavedCfg cid bid . Blob $ Cfg.toTransport identity cfg ]

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
    cfg <- select cfgTable
    restrict (cfg ! #cfgId .== literal cid)
    return cfg

getCfg :: MonadDb m => CfgId -> m (Maybe PilCfg)
getCfg cid = fmap (view #cfg) <$> getSavedCfg cid >>= \case
  [] -> return Nothing
  [Blob x] -> return . Just . Cfg.fromTransport $ x
  _ -> -- hopefully impossible
    P.error $ "PRIMARY KEY apparently not UNIQUE for id: " <> show cid

getCfgBinaryHash :: MonadDb m => CfgId -> m (Maybe BinaryHash)
getCfgBinaryHash cid = withDb $ do
  xs <- query $ do
    cfg <- select cfgTable
    restrict (cfg ! #cfgId .== literal cid)
    branch <- select snapshotBranchTable
    restrict (branch ! #branchId .== cfg ! #branchId)
    return $ branch ! #bndbHash
  case xs of
    [] -> return Nothing
    [h] -> return $ Just h
    _ -> P.error "getCfgBinaryHash: returned multiple branch ids"

getCfgBranchId :: MonadDb m => CfgId -> m (Maybe BranchId)
getCfgBranchId cid = withDb $ do
  xs <- query $ do
    cfg <- select cfgTable
    restrict (cfg ! #cfgId .== literal cid)
    return $ cfg ! #branchId
  case xs of
    [] -> return Nothing
    [h] -> return $ Just h
    _ -> P.error "getCfgBranchId: returned multiple branch ids"

  

-- | use `saveNewCfgAndBranch`
saveNewBranch_ :: MonadDb m
  => BranchId
  -> ClientId
  -> HostBinaryPath
  -> BinaryHash
  -> Snapshot.Branch BranchTree
  -> m ()
saveNewBranch_ bid cid hpath h b = withDb $
  insert_ snapshotBranchTable
    [ SnapshotBranch
      bid
      cid
      hpath
      h
      (b ^. #originFuncAddr)
      (b ^. #originFuncName)
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
    [SnapshotBranch _ _ hpath bhash originFuncAddr' fname mname rootNode' (Blob tree')] -> return
      . Just 
      . Snapshot.Branch hpath bhash originFuncAddr' fname mname rootNode'
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

getBranchesForFunction :: MonadDb m => ClientId -> HostBinaryPath -> Address -> m [(BranchId, Snapshot.Branch BranchTree)]
getBranchesForFunction cid hpath funcAddr = fmap (fmap f) . withDb . query $ do
  branch <- select snapshotBranchTable
  restrict (branch ! #originFuncAddr .== literal funcAddr
            .&& branch ! #clientId .== literal cid
            .&& branch ! #hostBinaryPath .== literal hpath
           )
  return branch
  where
    f :: SnapshotBranch -> (BranchId, Snapshot.Branch BranchTree)
    f (SnapshotBranch bid _ _ bhash faddr fname mname root (Blob tree')) =
      ( bid
      , Snapshot.Branch hpath bhash faddr fname mname root $ graphFromTransport tree'
      )

getAllBranchesForBinary :: MonadDb m => ClientId -> HostBinaryPath -> m [(BranchId, Snapshot.Branch BranchTree)]
getAllBranchesForBinary cid hpath = fmap (fmap f) . withDb . query $ do
  branch <- select snapshotBranchTable
  restrict ( branch ! #clientId .== literal cid
            .&& branch ! #hostBinaryPath .== literal hpath
           )
  return branch
  where
    f :: SnapshotBranch -> (BranchId, Snapshot.Branch BranchTree)
    f (SnapshotBranch bid _ _ bhash faddr fname mname root (Blob tree')) =
      ( bid
      , Snapshot.Branch hpath bhash faddr fname mname root $ graphFromTransport tree'
      )

getAllBranchesForClient :: MonadDb m => ClientId -> m (HashMap HostBinaryPath [(BranchId, Snapshot.Branch BranchTree)])
getAllBranchesForClient cid = fmap (HashMap.fromListWith (<>) . fmap f) . withDb . query $ do
  branch <- select snapshotBranchTable
  restrict ( branch ! #clientId .== literal cid )
  return branch
  where
    f :: SnapshotBranch -> (HostBinaryPath, [(BranchId, Snapshot.Branch BranchTree)])
    f (SnapshotBranch bid _ hpath bhash faddr fname mname root (Blob tree')) =
      ( hpath
      , [( bid
         , Snapshot.Branch hpath bhash faddr fname mname root $ graphFromTransport tree'
         )]
      )

