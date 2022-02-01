{-# LANGUAGE ConstraintKinds #-}
{-# LANGUAGE DataKinds #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Blaze.UI.Prelude
  ( module Exports
  , updateTVar
  , writeManyTQueue
  ) where

import Blaze.Prelude as Exports
import Control.Monad.Catch as Exports (MonadMask, MonadCatch, MonadThrow)
import Control.Lens.Extras as Exports (is)
import Control.Concurrent.STM.TQueue as Exports
import Control.Concurrent.STM.TVar as Exports
import Control.Concurrent.STM.TMVar as Exports
import Data.String.Conversions as Exports (ConvertibleStrings)
import Data.Aeson as Exports (ToJSONKey, FromJSONKey)
import Control.Monad.Extra as Exports (whenJust)

updateTVar :: TVar a -> (a -> a) -> STM ()
updateTVar tv f = readTVar tv >>= writeTVar tv . f

writeManyTQueue :: TQueue a -> [a] -> STM ()
writeManyTQueue q = mapM_ $ writeTQueue q

