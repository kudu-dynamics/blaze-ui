module Blaze.UI.Types.BinaryManager where

import Blaze.UI.Prelude
import Binja.Core (BNBinaryView)
import Blaze.UI.Types.BinaryHash (BinaryHash)
import qualified Data.HashMap.Strict as HashMap
import qualified Blaze.UI.Types.BinaryHash as BinaryHash
import System.Directory (createDirectoryIfMissing)
import qualified Data.ByteString as BS
import Blaze.UI.Types.HostBinaryPath (HostBinaryPath)
import qualified Blaze.UI.Types.HostBinaryPath as HBP
import Blaze.UI.Types.Session (ClientId(ClientId))


-- | Base directory where all versions of the BNDB are saved.
newtype BndbVersionsDir = BndbVersionsDir FilePath
  deriving (Eq, Ord, Read, Show, Generic)
  deriving newtype (IsString)
  deriving anyclass (FromJSON, ToJSON, Hashable)

-- | Main storage dir for Binary Manger.
newtype BinaryManagerStorageDir = BinaryManagerStorageDir FilePath
  deriving (Eq, Ord, Read, Show, Generic)
  deriving newtype (IsString)
  deriving anyclass (FromJSON, ToJSON, Hashable)

-- | Manages loading various versions of BNDBs
-- files are stored as `binVersionDir/<binhash>.bndb`
-- If a version is requested and not already in `cachedViews`,
-- it is loaded from filesystem into `cachedViews`.
data BinaryManager = BinaryManager
  {
    -- | Directory in which versioned BNDBs will be saved
    bndbVersionsDir :: BndbVersionsDir
    
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
  <> cs cid
  <> "/"
  <> HBP.encode p

getBndbPath_ :: BndbVersionsDir -> BinaryHash -> FilePath
getBndbPath_ (BndbVersionsDir vdir) h
  =  vdir
  <> "/"
  <> BinaryHash.toText h
  <> ".bndb"

getBndbPath :: BinaryManager -> BinaryHash -> FilePath
getBndbPath bm = getBndbPath_ $ bm ^. #bndbVersionsDir

-- | Saves bytestring of BNDB to the proper place in the binary manager folder.
-- Called by web server upon BNDB upload.
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
  
create :: BinaryManagerStorageDir -> ClientId -> HostBinaryPath -> STM BinaryManager
create bmdir cid bpath = BinaryManager
  (getBndbVersionsDir bmdir cid bpath)
  <$> newTVar HashMap.empty

data BinaryManagerError
  = FileDoesNotExist FilePath
  | OpenBndbError Text
  deriving (Eq, Ord, Show, Generic)

