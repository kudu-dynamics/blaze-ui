module Blaze.UI.Types.CachedCalc where

import Blaze.UI.Prelude
import qualified Data.HashMap.Strict as HashMap


-- TODO: add option to persist to db
newtype CachedCalc k v = CachedCalc
  { cache :: TVar (HashMap k (TMVar v)) 
  } deriving (Generic)

create :: STM (CachedCalc k v)
create = fmap CachedCalc . newTVar $ HashMap.empty

-- | Creates empty TMVar for k, calculates action in thread,
-- then inserts new v into TMVar.
-- The empty TMVar is created separately so things can start waiting on it
-- before calculation finishes.
setCalc :: (Eq k, Hashable k) => k -> IO v -> CachedCalc k v -> IO (TMVar v)
setCalc k action (CachedCalc cc) = do
  tmvar <- atomically $ do
    m <- readTVar cc
    case HashMap.lookup k m of
      Just v -> return v
      Nothing -> do
        emptyV <- newEmptyTMVar
        writeTVar cc $ HashMap.insert k emptyV m
        return emptyV
  void . forkIO $ do
    v <- action
    void . atomically $ tryPutTMVar tmvar v
  return tmvar

-- | Retrieves the cached calc. Returns Nothing
-- if the key cannot be found. Otherwise,
-- it waits until v is available.
getCalc :: (Hashable k, Eq k) => k -> CachedCalc k v -> IO (Maybe v)
getCalc k (CachedCalc cc) = (HashMap.lookup k <$> readTVarIO cc) >>= \case
  Nothing -> return Nothing
  Just tmvar -> fmap Just . atomically . readTMVar $ tmvar
