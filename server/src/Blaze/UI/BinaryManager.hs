module Blaze.UI.BinaryManager
  ( module Exports
  , module Blaze.UI.BinaryManager
  ) where

import Blaze.UI.Prelude
import Binja.Core (BNBinaryView)
import Blaze.UI.Types.BinaryHash (BinaryHash)
import qualified Blaze.UI.Types.BinaryHash as BinaryHash
import Blaze.UI.Types.BinaryManager
import System.Directory (copyFile, removeFile, doesFileExist)
import qualified Binja.Core as BN
import qualified Data.HashMap.Strict as HashMap
import qualified Blaze.UI.Types.BinaryManager as Exports

-- | Saves a new version of the bndb to the filesystem
-- | updates `latestVersion` in BinaryManager
saveNewVersion :: MonadIO m => BinaryManager -> FilePath -> m ()
saveNewVersion bm binPath = do
  h <- BinaryHash.fromFile binPath
  liftIO $ do
    copyFile binPath (getBndbPath bm h)
    removeFile binPath
    atomically . writeTVar (bm ^. #latestVersion) $ h

cacheBinaryView :: MonadIO m => BinaryManager -> BinaryHash -> BNBinaryView -> m ()
cacheBinaryView bm h bv = liftIO . atomically $ do
  m <- readTVar $ bm ^. #cachedViews
  writeTVar (bm ^. #cachedViews) $ HashMap.insert h bv m

-- | Loads a BV from a file if it exists
-- Doesn't check BinaryManager cache or populate it with result
loadVersionFromFile :: MonadIO m => BinaryManager -> BinaryHash -> m (Either BinaryManagerError BNBinaryView)
loadVersionFromFile bm h = do
  let fp = getBndbPath bm h
  liftIO $ doesFileExist fp >>= \case
    False -> return . Left $ FileDoesNotExist fp
    True -> do
      ebv <- BN.getBinaryView fp
      case ebv of
        Left err -> do
          return . Left . OpenBndbError $ err
        Right bv -> do
          BN.updateAnalysisAndWait bv
          return . Right $ bv

loadVersionFromCache :: MonadIO m => BinaryManager -> BinaryHash -> m (Maybe BNBinaryView)
loadVersionFromCache bm h = liftIO . atomically $ do
  m <- readTVar $ bm ^. #cachedViews
  return $ HashMap.lookup h m

-- | Gets a version of bndb; checks `binaryViews` first, then filesystem
loadBndb :: MonadIO m => BinaryManager -> BinaryHash -> m (Either BinaryManagerError BNBinaryView)
loadBndb bm h = loadVersionFromCache bm h >>= \case
  Just bv -> return $ Right bv
  Nothing -> loadVersionFromFile bm h >>= \case
    Left err -> return $ Left err
    Right bv -> do
      cacheBinaryView bm h bv
      return $ Right bv

loadLatest :: MonadIO m => BinaryManager -> m (Either BinaryManagerError BNBinaryView)
loadLatest bm = do
  h <- liftIO . atomically . readTVar $ bm ^. #latestVersion
  loadBndb bm h

  
