{-# LANGUAGE ConstraintKinds #-}
{-# LANGUAGE DataKinds #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Blaze.UI.Prelude
  ( module Exports
  , Streaming
  , StreamingIO
  , PPrint(PPrint)
  , catchEither
  , liftListM
  , liftListIO
  , liftEitherIO
  , liftMaybeIO
  , liftEitherM
  , liftMaybe
  , liftMaybeM
  , liftMaybeTIO
  , pshow
  , pprint
  , pairs
  , indexed
  , hdebug
  , twaddleUUID
  , unfoldWhileJustM
  ) where

--import qualified Prelude as P

--import Data.Typeable as Exports

import Control.Concurrent.Async as Exports (mapConcurrently)
import Control.Lens as Exports
  ( (%=),
    (%~),
    (.=),
    (.~),
    (?~),
    Iso',
    Lens',
    (^.),
    (^?),
    (^?!),
    iso,
    lens,
    makeClassy,
    makeClassyPrisms,
    makeFields,
    makeFieldsNoPrefix,
    makeLenses,
    makePrisms,
    over,
    use,
    view,
    _Just,
    _Right,
    _Left,
    _1,
    _2,
    _3,
    _4,
    _5,
  )
import Control.Monad.Trans.Class as Exports (MonadTrans)
import Control.Monad.Trans.Maybe as Exports (MaybeT, runMaybeT)
import Data.BinaryAnalysis as Exports
  ( Address (Address),
    AddressWidth (AddressWidth),
    Bits (Bits),
    Bytes (Bytes),
    toBits,
    toBytes,
    BitOffset (BitOffset),
    ByteOffset (ByteOffset),
    toBitOffset,
    toByteOffset
  )
import Data.Coerce as Exports (coerce)
import Data.Data as Exports
import Data.HashMap.Strict as Exports (HashMap)
import Data.HashSet as Exports (HashSet)
import Data.Maybe as Exports (fromJust)
import Data.String.Conversions as Exports (cs)
import qualified Data.Text.Lazy as L (Text)
import Data.UUID as Exports (UUID)
import qualified Data.UUID as UUID
import Protolude as Exports hiding (Bits, Fixity, Infix, Prefix, head)
import Streamly as Exports
  ( IsStream,
    asyncly,
  )
import qualified Streamly.Prelude
import System.IO.Unsafe (unsafePerformIO)
import System.Random as Exports (randomIO)
import Text.Pretty.Simple as PP
import Prelude as Exports
  ( (!!),
    String,
    head,
    error,
  )
import qualified GHC.Show

type Streaming t m = (Monad m, Monad (t m), MonadTrans t, IsStream t)

type StreamingIO t m = (Monad m, Monad (t m), MonadTrans t, IsStream t, MonadIO m, MonadIO (t m))

liftListM :: Streaming t m => m [a] -> t m a
liftListM = Streamly.Prelude.fromList <=< lift

liftListIO :: (StreamingIO t m) => IO [a] -> t m a
liftListIO = liftListM . liftIO

liftMaybe :: MonadError e m => e -> Maybe a -> m a
liftMaybe e Nothing = throwError e
liftMaybe _ (Just x) = return x

liftMaybeM :: Monad m => e -> m (Maybe a) -> ExceptT e m a
liftMaybeM e m = ExceptT $ m >>= return . maybe (Left e) Right

--sort of redundant, actually...
liftEitherM :: m (Either e a) -> ExceptT e m a
liftEitherM = ExceptT

liftEither :: (MonadError e m) => Either e a -> m a
liftEither (Left e) = throwError e
liftEither (Right x) = return x

catchEither :: MonadError e m => m a -> m (Either e a)
catchEither m = catchError (Right <$> m) $ return . Left

liftEitherIO :: (MonadError e m, MonadIO m) => IO (Either e a) -> m a
liftEitherIO m = liftIO m >>= liftEither

liftMaybeIO :: (MonadError e m, MonadIO m) => e -> IO (Maybe a) -> m a
liftMaybeIO e m = liftIO m >>= liftEither . maybe (Left e) Right

liftMaybeTIO :: MonadIO m => IO (Maybe a) -> MaybeT m a
liftMaybeTIO m = liftIO m >>= maybe mzero return

ppOptions :: PP.OutputOptions
ppOptions = PP.defaultOutputOptionsNoColor {PP.outputOptionsIndentAmount = 2}

pshow :: Show a => a -> L.Text
pshow = PP.pShowOpt ppOptions

pprint :: Show a => a -> IO ()
pprint = PP.pPrintOpt PP.NoCheckColorTty ppOptions

pairs :: [a] -> [(a, a)]
pairs xs = zip xs $ drop 1 xs

indexed :: [a] -> [(Int, a)]
indexed = zip [0 ..]

-- hardcore debug
hdebug :: b -> IO () -> b
hdebug x f = unsafePerformIO $ f >> return x

twaddleUUID :: Word32 -> UUID -> UUID
twaddleUUID diff' uuid =
  UUID.fromWords (w1 + diff') (w2 + diff') (w3 + diff') (w4 + diff')
  where
    (w1, w2, w3, w4) = UUID.toWords uuid

unfoldWhileJustM :: Monad m => m (Maybe a) -> m [a]
unfoldWhileJustM p = do
  y <- p 
  case y of
    Just z -> (z: ) <$> unfoldWhileJustM p
    _ -> return []


newtype PPrint a = PPrint a
  deriving (Eq, Ord, Generic)

instance Show a => Show (PPrint a) where
  show (PPrint x) = cs $ pshow x
