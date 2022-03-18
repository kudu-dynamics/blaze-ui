{-# LANGUAGE ConstraintKinds #-}
{-# LANGUAGE DataKinds #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Blaze.UI.Prelude
  ( module Exports
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
import Web.Scotty (Parsable(parseParam))


writeManyTQueue :: TQueue a -> [a] -> STM ()
writeManyTQueue q = mapM_ $ writeTQueue q

instance Parsable Bytes where
  parseParam s = case readMaybe (cs s) of
    Nothing -> Left $ "Not a number: " <> s
    Just n -> Right $ Bytes n

instance Parsable Address where
  parseParam s = Address <$> parseParam s
