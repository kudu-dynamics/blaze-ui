{-# OPTIONS_GHC -fno-warn-orphans #-}

module Blaze.UI.Types.Db where

import Blaze.UI.Prelude hiding ((:*:))

import qualified Prelude as P
import Database.Selda
import Database.Selda.SQLite
import Blaze.UI.Types.Cfg (CfgId, CfgTransport)
import Blaze.Types.Pil (Stmt)
import qualified Data.Aeson as Aeson
import Database.Selda.SqlType ( Lit(LBlob, LCustom)
                              , SqlTypeRep(TBlob)
                              , SqlValue(SqlBlob)
                              )
import Blaze.UI.Types.Graph (GraphTransport)
import Blaze.UI.Types.Cfg.Snapshot (BranchId, SnapshotType)
import Blaze.UI.Types.BndbHash (BndbHash)
import Blaze.UI.Types.HostBinaryPath (HostBinaryPath)
import Blaze.UI.Types.Session (ClientId)
import Database.Selda.Backend (SeldaConnection, runSeldaT)
import Blaze.UI.Types.Db.Address ()


newtype Conn = Conn (TMVar (SeldaConnection SQLite))

newtype Blob a = Blob { unBlob :: a }
  deriving (Eq, Ord, Show, Generic, Typeable)

instance (ToJSON a, FromJSON a, Typeable (Blob a)) => SqlType (Blob a) where
   mkLit (Blob x) = LCustom TBlob . LBlob . cs . Aeson.encode $ x

   sqlType _ = TBlob

   fromSql (SqlBlob s) = case Aeson.decode (cs s) of
     Nothing -> P.error "Could not convert json blob"
     Just x -> Blob x
   fromSql x = P.error $ "Unexpected sql field type: " <> show x

   defaultValue = LCustom TBlob (LBlob "")

data SavedCfg = SavedCfg
  { cfgId :: CfgId
  , branchId :: BranchId
  , name :: Maybe Text
  , created :: UTCTime
  , modified :: UTCTime
  , snapshotType :: SnapshotType
  , cfg :: Blob (CfgTransport [Stmt])
  } deriving (Generic, SqlRow)

data SnapshotBranch = SnapshotBranch
  { branchId :: BranchId
  , clientId :: ClientId
  , hostBinaryPath :: HostBinaryPath
  , bndbHash :: BndbHash
  , originFuncAddr :: Address
  , originFuncName :: Text
  , branchName :: Maybe Text
  , rootNode :: CfgId
  , tree :: Blob (GraphTransport () () CfgId)
  } deriving (Generic, SqlRow)

cfgTable :: Table SavedCfg
cfgTable = table "cfg" [#cfgId :- primary]

snapshotBranchTable :: Table SnapshotBranch
snapshotBranchTable = table "snapshotBranch" [#branchId :- primary]

open :: FilePath -> IO Conn
open dbPath = do
  c <- sqliteOpen dbPath
  Conn <$> newTMVarIO c

close :: Conn -> IO ()
close = flip withConn seldaClose

withConn :: MonadIO m => Conn -> (SeldaConnection SQLite-> m a) -> m a
withConn (Conn tconn) f = do
  conn <- liftIO . atomically $ takeTMVar tconn
  r <- f conn
  liftIO . atomically $ putTMVar tconn conn
  return r

runSelda :: (MonadMask m, MonadIO m) => Conn -> SeldaT SQLite m a -> m a
runSelda conn m = withConn conn (runSeldaT m)

class (MonadMask m, MonadIO m, Monad m) => MonadDb m where
  withDb :: SeldaT SQLite m a -> m a

onlyOne :: [a] -> Maybe a
onlyOne [] = Nothing
onlyOne [x] = Just x
onlyOne _ = P.error "Expected only one result"
