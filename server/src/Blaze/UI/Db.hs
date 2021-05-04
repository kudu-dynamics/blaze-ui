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
import Blaze.UI.Types.Cfg.Snapshot (BranchId, BranchTree)
import qualified Blaze.UI.Types.Graph as Graph
import Blaze.UI.Types.Graph (graphFromTransport)


init :: FilePath -> IO ()
init blazeSqliteFilePath = withSQLite blazeSqliteFilePath $ do
  tryCreateTable cfgTable
  tryCreateTable snapshotBranchTable

withDb :: SeldaT SQLite EventLoop a -> EventLoop a
withDb m = do
  ctx <- ask
  withSQLite (ctx ^. #sqliteFilePath) m

saveCfg :: CfgId -> Maybe Text -> PilCfg -> EventLoop ()
saveCfg cid mname cfg' = withDb $ do
  utc <- liftIO getCurrentTime
  insert_ cfgTable
    [ SavedCfg cid mname utc utc . Blob $ Cfg.toTransport identity cfg' ]

setCfgName :: Text -> CfgId -> EventLoop ()
setCfgName name' cid = withDb $ do
  update_ cfgTable
    (\immCfg -> immCfg ! #cfgId .== literal cid)
    (\immCfg -> immCfg `with` [ #name := just (literal name')])

updateCfg :: CfgId -> PilCfg -> EventLoop ()
updateCfg cid pcfg = withDb $ do
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

-- | Saves snapshot branch, overwriting previous branch with same id.
-- This means atm that co-editing snapshot branches won't really work
saveBranch :: BranchId
           -> Function
           -> CfgId
           -> BranchTree
           -> EventLoop ()
saveBranch bid originFunc' rootNode' branchTree = withDb $ do
  insert_ snapshotBranchTable
    [ SnapshotBranch bid (Blob originFunc') rootNode'
      . Blob $ Graph.graphToTransport branchTree
    ]

getBranch :: BranchId -> EventLoop (Maybe Snapshot.Branch)
getBranch bid = withDb $ do
  xs <- query $ do
    branch <- select snapshotBranchTable
    restrict (branch ! #branchId .== literal bid)
    return branch
  case xs of
    [] -> return Nothing
    [SnapshotBranch _ (Blob originFunc') rootNode' (Blob tree')] -> return
      . Just 
      . Snapshot.Branch originFunc' rootNode'
      . graphFromTransport
      $ tree'
    _ -> -- hopefully impossible
      P.error $ "PRIMARY KEY apparently not UNIQUE for id: " <> show bid

