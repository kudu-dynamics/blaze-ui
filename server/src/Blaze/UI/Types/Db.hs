{-# LANGUAGE InstanceSigs #-}
module Blaze.UI.Types.Db where

import Blaze.UI.Prelude hiding ((:*:))

import qualified Prelude as P
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
import Database.Selda.SqlType ( Lit(LBlob, LText, LCustom)
                              , SqlTypeRep(TBlob, TText)
                              , SqlValue(SqlBlob, SqlString)
                              )
import System.Directory (doesFileExist)
import Blaze.UI.Types (EventLoop)
import Blaze.UI.Types.Graph (GraphTransport, graphToTransport, graphFromTransport)
import Blaze.UI.Types.Cfg.Snapshot (BranchId, SnapshotInfo)

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
  , name :: Maybe Text
  , created :: UTCTime
  , modified :: UTCTime
  , branchId :: BranchId
  , cfg :: Blob (CfgTransport [Stmt])
  } deriving Generic
instance SqlRow SavedCfg

data SnapshotBranch = SnapshotBranch
  { branchId :: BranchId
  , originFuncAddr :: Address
  , branchName :: Maybe Text
  , rootNode :: CfgId
  , tree :: Blob (GraphTransport () SnapshotInfo CfgId)
  } deriving Generic
instance SqlRow SnapshotBranch

cfgTable :: Table SavedCfg
cfgTable = table "cfg" [#cfgId :- primary]

snapshotBranchTable :: Table SnapshotBranch
snapshotBranchTable = table "snapshotBranch" [#branchId :- primary]
