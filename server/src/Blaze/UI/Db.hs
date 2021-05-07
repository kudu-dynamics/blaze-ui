module Blaze.UI.Db
  ( module Blaze.UI.Db
  , module Exports
  ) where

import Blaze.UI.Prelude hiding ((:*:))

import qualified Prelude as P
import Blaze.UI.Types.Db as Exports
import Database.Selda
import Database.Selda.SQLite
import Blaze.UI.Types.Cfg (CfgId(CfgId), CfgTransport)
import Blaze.Types.Cfg (PilCfg)
import qualified Blaze.UI.Types.Cfg as Cfg
import Blaze.Types.Pil (Stmt)
import Blaze.Function (Function)
import qualified Data.Aeson as Aeson
import Unsafe.Coerce (unsafeCoerce)
import qualified Database.Selda.SqlType as SqlT
import Database.Selda.SqlType ( Lit(LBlob, LCustom)
                              , SqlTypeRep(TBlob)
                              , SqlValue(SqlBlob)
                              )
import System.Directory (doesFileExist)
import Blaze.UI.Types (EventLoop)
import Data.Time.Clock (getCurrentTime)
import qualified Blaze.UI.Types.Cfg.Snapshot as Snapshot
import Blaze.UI.Types.Cfg.Snapshot (BranchId, BranchTree, SnapshotInfo(SnapshotInfo))
import qualified Blaze.UI.Cfg.Snapshot as Snapshot
import qualified Blaze.UI.Types.Graph as Graph
import Blaze.UI.Types.Graph (graphFromTransport, graphToTransport)


init :: FilePath -> IO ()
init blazeSqliteFilePath = withSQLite blazeSqliteFilePath $ do
  tryCreateTable cfgTable
  tryCreateTable snapshotBranchTable

withDb :: SeldaT SQLite EventLoop a -> EventLoop a
withDb m = do
  ctx <- ask
  withSQLite (ctx ^. #sqliteFilePath) m

-- | Only called when creating a fresh CFG from a function
saveNewCfgAndBranch :: Address -> PilCfg -> EventLoop (BranchId, CfgId)
saveNewCfgAndBranch originFuncAddr' pcfg = do
  cid <- liftIO randomIO
  bid <- liftIO randomIO
  utc <- liftIO getCurrentTime
  saveNewCfg_ bid cid pcfg
  let b = Snapshot.singletonBranch originFuncAddr' Nothing cid
          $ SnapshotInfo Nothing utc Snapshot.AutoSave
  saveNewBranch_ bid b
  return (bid, cid)
    

-- | use `saveNewCfgAndBranch` instead
saveNewCfg_ :: BranchId -> CfgId -> PilCfg -> EventLoop ()
saveNewCfg_ bid cid cfg' = withDb $ do
  utc <- liftIO getCurrentTime
  insert_ cfgTable
    [ SavedCfg cid Nothing utc utc bid . Blob $ Cfg.toTransport identity cfg' ]


setCfgName :: CfgId -> Text -> EventLoop ()
setCfgName cid name' = withDb $ do
  update_ cfgTable
    (\cfg' -> cfg' ! #cfgId .== literal cid)
    (\cfg' -> cfg' `with` [ #name := just (literal name')])

setCfg :: CfgId -> PilCfg -> EventLoop ()
setCfg cid pcfg = withDb $ do
  utc <- liftIO getCurrentTime
  update_ cfgTable
    (\immCfg -> immCfg ! #cfgId .== literal cid)
    (\immCfg -> immCfg `with` [ #cfg := literal (Blob $ Cfg.toTransport identity pcfg)
                              , #modified := literal utc
                              ])

getSavedCfg :: CfgId -> EventLoop [SavedCfg]
getSavedCfg cid = withDb $ do
  query $ do
    cfg' <- select cfgTable
    restrict (cfg' ! #cfgId .== literal cid)
    return $ cfg'

getCfg :: CfgId -> EventLoop (Maybe PilCfg)
getCfg cid = (fmap $ view #cfg) <$> getSavedCfg cid >>= \case
  [] -> return Nothing
  [Blob x] -> return . Just . Cfg.fromTransport $ x
  _ -> -- hopefully impossible
    P.error $ "PRIMARY KEY apparently not UNIQUE for id: " <> show cid

-- | use `saveNewCfgAndBranch`
saveNewBranch_ :: BranchId
              -> Snapshot.Branch BranchTree
              -> EventLoop ()
saveNewBranch_ bid b = withDb $
  insert_ snapshotBranchTable
    [ SnapshotBranch
      bid
      (b ^. #originFuncAddr)
      (b ^. #branchName)
      (b ^. #rootNode)
      . Blob
      . Graph.graphToTransport
      $ b ^. #tree
    ]

setBranchTree :: BranchId -> BranchTree -> EventLoop ()
setBranchTree bid branchTree = withDb $ do
  update_ snapshotBranchTable
    (\b -> b ! #branchId .== literal bid)
    (\b -> b `with` [ #tree := literal (Blob . graphToTransport $ branchTree) ])

getBranch :: BranchId -> EventLoop (Maybe (Snapshot.Branch BranchTree))
getBranch bid = withDb $ do
  xs <- query $ do
    branch <- select snapshotBranchTable
    restrict (branch ! #branchId .== literal bid)
    return branch
  case xs of
    [] -> return Nothing
    [SnapshotBranch _ originFuncAddr' mname rootNode' (Blob tree')] -> return
      . Just 
      . Snapshot.Branch originFuncAddr' mname rootNode'
      . graphFromTransport
      $ tree'
    _ -> -- hopefully impossible
      P.error $ "PRIMARY KEY apparently not UNIQUE for id: " <> show bid


getBranchesForFunction :: Address -> EventLoop [(BranchId, Snapshot.Branch BranchTree)]
getBranchesForFunction funcAddr = fmap (fmap f) . withDb . query $ do
  branch <- select snapshotBranchTable
  restrict (branch ! #originFuncAddr .== literal funcAddr)
  return branch
  where
    f :: SnapshotBranch -> (BranchId, Snapshot.Branch BranchTree)
    f (SnapshotBranch bid faddr mname root (Blob tree')) =
      ( bid
      , Snapshot.Branch faddr mname root $ graphFromTransport tree'
      )

