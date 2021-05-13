module Blaze.UI.Types.BinaryManager where

import Blaze.UI.Prelude
import Binja.Core (BNBinaryView)
import Blaze.UI.Types.BinaryHash (BinaryHash)
import qualified Data.HashMap.Strict as HashMap
import Blaze.UI.Types.BinaryHash (BinaryHash(BinaryHash), getBinaryHash)
import System.Directory (copyFile, removeFile, doesFileExist, createDirectoryIfMissing)

-- | Manages loading various versions of Bndbs
-- files are stored as binVersionDir/<binhash>.bndb
-- If a version is requested and not already in binaryViews,
-- it is loaded from filesystem into binaryViews
data BinaryManager = BinaryManager
  {
    -- dir that versioned dirs will be saved in
    versionDir :: FilePath
  
  -- latest version is empty if there are no versions saved yet
  , latestVersion :: TVar BinaryHash
  
  -- TODO: make binary views into resource pool with expiries
  -- right now they just get stored here forever
  , binaryViews :: TVar (HashMap BinaryHash BNBinaryView)
  } deriving (Generic)

bndbVersionPath_ :: FilePath -> BinaryHash -> FilePath
bndbVersionPath_ versionDir' (BinaryHash h)
  =  versionDir'
  <> "/"
  <> (cs h)
  <> ".bndb"

bndbVersionPath :: BinaryManager -> BinaryHash -> FilePath
bndbVersionPath bm = bndbVersionPath_ $ bm ^. #versionDir


-- | Saves a new version of the bndb to the filesystem
-- | updates `latestVersion` in BinaryManager
saveVersion_ :: MonadIO m => FilePath -> FilePath -> BinaryHash -> m ()
saveVersion_ versionDir' binPath h = liftIO $ do
  let versionFileDest = bndbVersionPath_ versionDir' h
  copyFile binPath versionFileDest
  -- TODO: uncomment this once we make sure UI only sends copy
  -- and doesn't point to original
  -- removeFile binPath
                        

-- TODO: crashes if initial file not found
create :: MonadIO m => FilePath -> FilePath -> m BinaryManager
create bndbStorageDirFromEnv initialBndbFile = do
  liftIO $ createDirectoryIfMissing True versionDir'
  h <- getBinaryHash initialBndbFile
  saveVersion_ versionDir' initialBndbFile h
  BinaryManager versionDir' <$> liftIO (newTVarIO h) <*> liftIO (newTVarIO HashMap.empty)
  where
    versionDir' = bndbStorageDirFromEnv <> "/" <> initialBndbFile

data BinaryManagerError
  = FileDoesNotExist FilePath
  | OpenBndbError Text
  deriving (Eq, Ord, Show, Generic)

