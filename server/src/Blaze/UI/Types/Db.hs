{-# OPTIONS_GHC -fno-warn-orphans #-}

module Blaze.UI.Types.Db where

import Blaze.UI.Prelude hiding ((:*:))

import qualified Prelude as P
import Database.Selda
import Database.Selda.SQLite
import Blaze.UI.Types.Cfg (CfgId, CfgTransport)
import Blaze.Types.Pil (Stmt)
import qualified Data.Aeson as Aeson
import Database.Selda.SqlType ( Lit(LBlob, LText, LCustom)
                              , SqlTypeRep(TBlob, TText)
                              , SqlValue(SqlBlob, SqlString)
                              )
import Blaze.UI.Types.Graph (GraphTransport)
import Blaze.UI.Types.Cfg.Snapshot (BranchId, SnapshotType)
import Blaze.UI.Types.BinaryHash (BinaryHash)
import Blaze.UI.Types.HostBinaryPath (HostBinaryPath)
import Blaze.UI.Types.Session (ClientId)
import Database.Selda.Backend (SeldaConnection, runSeldaT)


newtype Conn = Conn (SeldaConnection SQLite)

newtype Blob a = Blob a
  deriving (Eq, Ord, Show, Generic, Typeable)

instance (ToJSON a, FromJSON a, Typeable (Blob a)) => SqlType (Blob a) where
   mkLit (Blob x) = LCustom TBlob . LBlob . cs . Aeson.encode $ x

   sqlType _ = TBlob

   fromSql (SqlBlob s) = case Aeson.decode (cs s) of
     Nothing -> P.error "Could not convert json blob"
     Just x -> Blob x
   fromSql x = P.error $ "Unexpected sql field type: " <> show x

   defaultValue = LCustom TBlob (LBlob "")

-- oh no, it's an orphan!
instance SqlType Address where
   mkLit (Address (Bytes x)) = LCustom TBlob . LText . show $ x

   sqlType _ = TText

   fromSql (SqlString s) = case readMaybe (cs s) of
     Nothing -> P.error $ "Cannot convert " <> cs s <> " to Address"
     Just n -> Address . Bytes $ n
   fromSql x = P.error $ "Unexpected sql field type: " <> show x

   defaultValue = LCustom TText (LText "")

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
  , bndbHash :: BinaryHash
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

runSelda :: (MonadMask m, MonadIO m) => Conn -> SeldaT SQLite m a -> m a
runSelda (Conn conn) m = runSeldaT m conn

class (MonadMask m, MonadIO m, Monad m) => MonadDb m where
  withDb :: SeldaT SQLite m a -> m a
