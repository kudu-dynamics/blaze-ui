module Blaze.UI.Types.BinaryManager where

import Blaze.UI.Prelude
import Binja.Core (BNBinaryView)
import Blaze.UI.Types.BinaryHash (BinaryHash)
import qualified Data.HashMap.Strict as HashMap
import Blaze.UI.Types.BinaryHash (BinaryHash(BinaryHash))
import qualified Blaze.UI.Types.BinaryHash as BinaryHash
import System.Directory (copyFile, removeFile, doesFileExist, createDirectoryIfMissing)
import qualified Data.ByteString as BS
import Blaze.UI.Types.HostBinaryPath (HostBinaryPath)
import qualified Blaze.UI.Types.HostBinaryPath as HBP
import qualified Data.UUID as UUID
import Blaze.UI.Types.Session (ClientId(ClientId))


-- | Base dir where all the versions of the bndb are saved
newtype BndbVersionsDir = BndbVersionsDir FilePath
  deriving (Eq, Ord, Read, Show, Generic)
  deriving newtype (IsString)
  deriving anyclass (FromJSON, ToJSON, Hashable)

-- | Main storage dir for BM. From env
newtype BinaryManagerStorageDir = BinaryManagerStorageDir FilePath
  deriving (Eq, Ord, Read, Show, Generic)
  deriving newtype (IsString)
  deriving anyclass (FromJSON, ToJSON, Hashable)


-- | Manages loading various versions of Bndbs
-- files are stored as binVersionDir/<binhash>.bndb
-- If a version is requested and not already in binaryViews,
-- it is loaded from filesystem into binaryViews
data BinaryManager = BinaryManager
  {
    -- dir that versioned bndbs will be saved in
    bndbVersionsDir :: BndbVersionsDir
  
  -- latest version is empty if there are no versions saved yet
  , latestVersion :: TVar BinaryHash
  
  -- TODO: make binary views into resource pool with expiries
  -- right now they just get stored here forever
  , cachedViews :: TVar (HashMap BinaryHash BNBinaryView)
  } deriving (Generic)

getBndbVersionsDir :: BinaryManagerStorageDir
                   -> ClientId
                   -> HostBinaryPath
                   -> BndbVersionsDir
getBndbVersionsDir (BinaryManagerStorageDir bmdir) (ClientId cid) p = BndbVersionsDir $
  bmdir
  <> "/"
  <> cs (UUID.toText cid)
  <> "/"
  <> HBP.encode p

getBndbPath_ :: BndbVersionsDir -> BinaryHash -> FilePath
getBndbPath_ (BndbVersionsDir vdir) h
  =  vdir
  <> "/"
  <> BinaryHash.toString h
  <> ".bndb"

getBndbPath :: BinaryManager -> BinaryHash -> FilePath
getBndbPath bm = getBndbPath_ $ bm ^. #bndbVersionsDir

-- -- | Saves a new version of the bndb to the filesystem
-- -- | updates `latestVersion` in BinaryManager
-- saveVersion_ :: MonadIO m => BndbVersionsDir -> FilePath -> BinaryHash -> m ()
-- saveVersion_ versionDir' binPath h = liftIO $ do
--   let versionFileDest = bndbVersionPath_ versionDir' h
--   copyFile binPath versionFileDest
--   -- TODO: uncomment this once we make sure UI only sends copy
--   -- and doesn't point to original
--   -- removeFile binPath

-- to be called by web server with file uploader
saveBndbBytestring :: MonadIO m => BinaryManagerStorageDir -> ClientId -> HostBinaryPath -> ByteString -> m BinaryHash
saveBndbBytestring bmdir cid hpath s = do
  liftIO $ createDirectoryIfMissing True versionsDir'
  let h = BinaryHash.fromByteString s
      bndbVersionFileDest = getBndbPath_ versionsDir h
  liftIO . BS.writeFile bndbVersionFileDest $ s
  return h
  where
    versionsDir = getBndbVersionsDir bmdir cid hpath
    (BndbVersionsDir versionsDir') = versionsDir
  

-- TODO: crashes if initial file not found
-- createFromInitialFile :: MonadIO m => FilePath -> FilePath -> m BinaryManager
-- createFromInitialFile bndbStorageDirFromEnv initialBndbFile = do
--   liftIO $ createDirectoryIfMissing True versionDir'
--   h <- BinaryHash.fromFile initialBndbFile
--   saveVersion_ versionDir' initialBndbFile h
--   BinaryManager versionDir' <$> liftIO (newTVarIO h) <*> liftIO (newTVarIO HashMap.empty)
--   where
--     versionDir' = bndbStorageDirFromEnv <> "/" <> initialBndbFile

create :: MonadIO m => HostBinaryPath -> BinaryHash -> m (Either BinaryManagerError BinaryManager)
create bpath bhash = undefined

getLatestVersionHash :: MonadIO m => BinaryManager -> m BinaryHash
getLatestVersionHash bm = liftIO . readTVarIO $ bm ^. #latestVersion

data BinaryManagerError
  = FileDoesNotExist FilePath
  | OpenBndbError Text
  deriving (Eq, Ord, Show, Generic)

