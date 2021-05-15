{-# LANGUAGE ConstraintKinds #-}
{-# LANGUAGE DataKinds #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Blaze.UI.Prelude
  ( module Exports
  , writeManyTQueue
  ) where

--import Data.Typeable as Exports

import Blaze.Prelude as Exports
-- import Control.Concurrent.Async as Exports (mapConcurrently)
import Control.Monad.Catch as Exports (MonadMask, MonadCatch, MonadThrow)
-- import Control.Monad.Trans.Class as Exports (MonadTrans)
-- import Control.Monad.Trans.Maybe as Exports (MaybeT, runMaybeT)
-- import Data.Aeson as Exports (FromJSON, ToJSON)
-- import Data.BinaryAnalysis as Exports
--   ( Address (Address),
--     AddressWidth (AddressWidth),
--     Bits (Bits),
--     Bytes (Bytes),
--     toBits,
--     toBytes,
--     BitOffset (BitOffset),
--     ByteOffset (ByteOffset),
--     toBitOffset,
--     toByteOffset
--   )
-- import Data.Coerce as Exports (coerce)
-- import Data.Data as Exports
-- import Data.HashMap.Strict as Exports (HashMap)
-- import Data.HashSet as Exports (HashSet)
-- import Data.Maybe as Exports (fromJust)
-- import Data.String.Conversions as Exports (cs)
-- import qualified Data.Text.Lazy as L (Text)
-- import Data.UUID as Exports (UUID)
-- import qualified Data.UUID as UUID
-- import Protolude as Exports hiding (Bits, Fixity, Infix, Prefix, head)
-- import Streamly as Exports
--   ( IsStream,
--     asyncly,
--   )
-- import qualified Streamly.Prelude
-- import System.IO.Unsafe (unsafePerformIO)
-- import System.Random as Exports (randomIO)
-- import Text.Pretty.Simple as PP
-- import Prelude as Exports
--   ( (!!),
--     String,
--     head,
--     error,
--   )
import Control.Concurrent.STM.TQueue as Exports
import Control.Concurrent.STM.TVar as Exports
import Control.Concurrent.STM.TMVar as Exports
import Data.String.Conversions as Exports (ConvertibleStrings)
-- type Streaming t m = (Monad m, Monad (t m), MonadTrans t, IsStream t)

-- type StreamingIO t m = (Monad m, Monad (t m), MonadTrans t, IsStream t, MonadIO m, MonadIO (t m))

-- liftMaybe :: MonadError e m => e -> Maybe a -> m a
-- liftMaybe e Nothing = throwError e
-- liftMaybe _ (Just x) = return x

-- liftMaybeM :: Monad m => e -> m (Maybe a) -> ExceptT e m a
-- liftMaybeM e m = ExceptT $ m >>= return . maybe (Left e) Right

-- --sort of redundant, actually...
-- liftEitherM :: m (Either e a) -> ExceptT e m a
-- liftEitherM = ExceptT

-- liftEither :: (MonadError e m) => Either e a -> m a
-- liftEither (Left e) = throwError e
-- liftEither (Right x) = return x

-- catchEither :: MonadError e m => m a -> m (Either e a)
-- catchEither m = catchError (Right <$> m) $ return . Left

-- liftEitherIO :: (MonadError e m, MonadIO m) => IO (Either e a) -> m a
-- liftEitherIO m = liftIO m >>= liftEither

-- liftMaybeIO :: (MonadError e m, MonadIO m) => e -> IO (Maybe a) -> m a
-- liftMaybeIO e m = liftIO m >>= liftEither . maybe (Left e) Right

-- liftMaybeTIO :: MonadIO m => IO (Maybe a) -> MaybeT m a
-- liftMaybeTIO m = liftIO m >>= maybe mzero return

-- ppOptions :: PP.OutputOptions
-- ppOptions = PP.defaultOutputOptionsNoColor {PP.outputOptionsIndentAmount = 2}

-- pprint :: (MonadIO m, Show a) => a -> m ()
-- pprint = PP.pPrintOpt PP.NoCheckColorTty ppOptions

-- pputText :: MonadIO m => Text -> m ()
-- pputText = PP.pPrintString . cs

-- pairs :: [a] -> [(a, a)]
-- pairs xs = zip xs $ drop 1 xs

-- indexed :: [a] -> [(Int, a)]
-- indexed = zip [0 ..]

-- -- hardcore debug
-- hdebug :: b -> IO () -> b
-- hdebug x f = unsafePerformIO $ f >> return x

-- twaddleUUID :: Word32 -> UUID -> UUID
-- twaddleUUID diff' uuid =
--   UUID.fromWords (w1 + diff') (w2 + diff') (w3 + diff') (w4 + diff')
--   where
--     (w1, w2, w3, w4) = UUID.toWords uuid



-- newtype PPrint a = PPrint a
--   deriving (Eq, Ord, Generic)

-- instance Show a => Show (PPrint a) where
--   show (PPrint x) = cs $ pshow x

writeManyTQueue :: TQueue a -> [a] -> STM ()
writeManyTQueue q = mapM_ $ writeTQueue q
