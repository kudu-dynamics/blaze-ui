module Blaze.UI.Db
  ( module Blaze.UI.Db
  , module Exports
  ) where

import Blaze.UI.Prelude hiding ((:*:), Selector)

import qualified Prelude as P
import Blaze.UI.Types.Db as Exports hiding (cfg)
import Database.Selda
import Database.Selda.SQLite
import Blaze.UI.Types.Cfg (CfgId)
import Blaze.Types.Cfg (PilCfg)
import qualified Blaze.UI.Types.Cfg as Cfg
import Data.Time.Clock (getCurrentTime)
import qualified Blaze.UI.Types.Cfg.Snapshot as Snapshot
import Blaze.UI.Types.Cfg.Snapshot ( BranchId
                                   , BranchTree
                                   , SnapshotInfo(SnapshotInfo)
                                   , SnapshotType(Autosave)
                                   )
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
          $ SnapshotInfo Nothing utc utc Snapshot.Autosave
  saveNewBranch_ bid clientId' hpath bhash b
  return (bid, cid, b)

-- | use `saveNewCfgAndBranch` instead
saveNewCfg_ :: MonadDb m => BranchId -> CfgId -> PilCfg -> m ()
saveNewCfg_ bid cid cfg = withDb $ do
  utc <- liftIO getCurrentTime
  insert_ cfgTable
    [ SavedCfg cid bid Nothing utc utc Autosave . Blob $ Cfg.toTransport identity cfg ]

setCfgAttr :: (MonadDb m, SqlType a)
           => Selector SavedCfg a
           -> CfgId
           -> a
           -> m ()
setCfgAttr selector cid x = withDb $ do
  update_ cfgTable
    (\cfg -> cfg ! #cfgId .== literal cid)
    (\cfg -> cfg `with` [ selector := literal x])

setCfgName :: MonadDb m => CfgId -> Text -> m ()
setCfgName cid = setCfgAttr #name cid . Just

setCfgSnapshotType :: MonadDb m => CfgId -> SnapshotType -> m ()
setCfgSnapshotType = setCfgAttr #snapshotType

setCfg :: MonadDb m => CfgId -> PilCfg -> m ()
setCfg cid pcfg = withDb $ do
  utc <- liftIO getCurrentTime
  update_ cfgTable
    (\cfg' -> cfg' ! #cfgId .== literal cid)
    (\cfg' -> cfg' `with` [ #cfg := literal (Blob $ Cfg.toTransport identity pcfg)
                          , #modified := literal utc
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

onlyOne :: [a] -> Maybe a
onlyOne [] = Nothing
onlyOne [x] = Just x
onlyOne _ = P.error "Expected only one result"

getCfgType :: MonadDb m => CfgId -> m (Maybe SnapshotType)
getCfgType cid = withDb $ do
  fmap onlyOne . query $ do
    cfg <- select cfgTable
    restrict (cfg ! #cfgId .== literal cid)
    return $ cfg ! #snapshotType

getCfgBinaryHash :: MonadDb m => CfgId -> m (Maybe BinaryHash)
getCfgBinaryHash cid = withDb $ do
  fmap onlyOne . query $ do
    cfg <- select cfgTable
    restrict (cfg ! #cfgId .== literal cid)
    branch <- select snapshotBranchTable
    restrict (branch ! #branchId .== cfg ! #branchId)
    return $ branch ! #bndbHash

getCfgBranchId :: MonadDb m => CfgId -> m (Maybe BranchId)
getCfgBranchId cid = withDb $ do
  fmap onlyOne . query $ do
    cfg <- select cfgTable
    restrict (cfg ! #cfgId .== literal cid)
    return $ cfg ! #branchId

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

getBranchAttrs :: MonadDb m => BranchId -> m (HashMap CfgId SnapshotInfo)
getBranchAttrs bid = withDb $ do
  xs <- query $ do
    cfg <- select cfgTable
    restrict (cfg ! #branchId .== literal bid)
    return (    cfg ! #cfgId
            :*: cfg ! #name
            :*: cfg ! #created
            :*: cfg ! #modified
            :*: cfg ! #snapshotType
           )
  return . HashMap.fromList $ f <$> xs
  where
    f (cid :*: name' :*: created' :*: modified' :*: snaptype)
      = (cid, SnapshotInfo name' created' modified' snaptype)

getBranch :: MonadDb m => BranchId -> m (Maybe (Snapshot.Branch BranchTree))
getBranch bid = do
  attrs <- getBranchAttrs bid
  withDb $ do
    xs <- query $ do
      branch <- select snapshotBranchTable
      restrict (branch ! #branchId .== literal bid)
      return branch
    case xs of
      [] -> return Nothing
      [SnapshotBranch _ _ hpath bhash originFuncAddr' fname mname rootNode' (Blob tree')] -> return
        . Just 
        . Snapshot.Branch hpath bhash originFuncAddr' fname mname rootNode' attrs
        . graphFromTransport
        $ tree'
      _ -> -- hopefully impossible
        P.error $ "PRIMARY KEY apparently not UNIQUE for id: " <> show bid

-- | Gets all branches for specified branch ids. If a Branch cannot be found,
-- that branch is discarded.
getBranches :: forall m. MonadDb m => [BranchId] -> m [(BranchId, Snapshot.Branch BranchTree)]
getBranches = fmap catMaybes . traverse f
  where
    f :: BranchId -> m (Maybe (BranchId, Snapshot.Branch BranchTree))
    f bid = fmap (bid,) <$> getBranch bid

-- TODO: Add a lock so branch can't be opened while being modified
-- or make some abstraction were you just modify tvars and it updates the db
-- automatically
modifyBranchTree :: MonadDb m => BranchId -> (BranchTree -> BranchTree) -> m ()
modifyBranchTree bid f = getBranch bid >>= \case
  Nothing -> return ()
  Just b -> setBranchTree bid (f $ b ^. #tree)

getBranchesForFunction :: forall m. MonadDb m => ClientId -> HostBinaryPath -> Address -> m [(BranchId, Snapshot.Branch BranchTree)]
getBranchesForFunction cid hpath funcAddr = do
  bids <- withDb . query $ do
    branch <- select snapshotBranchTable
    restrict (branch ! #originFuncAddr .== literal funcAddr
              .&& branch ! #clientId .== literal cid
              .&& branch ! #hostBinaryPath .== literal hpath
             )
    return $ branch ! #branchId
  getBranches bids

getAllBranchesForBinary :: MonadDb m => ClientId -> HostBinaryPath -> m [(BranchId, Snapshot.Branch BranchTree)]
getAllBranchesForBinary cid hpath = do
  bids <- withDb . query $ do
    branch <- select snapshotBranchTable
    restrict ( branch ! #clientId .== literal cid
               .&& branch ! #hostBinaryPath .== literal hpath
             )
    return $ branch ! #branchId
  getBranches bids

getAllBranchesForClient :: MonadDb m => ClientId -> m (HashMap HostBinaryPath [(BranchId, Snapshot.Branch BranchTree)])
getAllBranchesForClient cid = do
  bids <- withDb . query $ do
    branch <- select snapshotBranchTable
    restrict ( branch ! #clientId .== literal cid )
    return $ branch ! #branchId
  branches <- getBranches bids
  return . HashMap.fromListWith (<>) . fmap f $ branches
  where
    f :: (BranchId, Snapshot.Branch BranchTree)
      -> (HostBinaryPath, [(BranchId, Snapshot.Branch BranchTree)])
    f (bid, branch) = ( branch ^. #hostBinaryPath
                       , [(bid, branch)])


