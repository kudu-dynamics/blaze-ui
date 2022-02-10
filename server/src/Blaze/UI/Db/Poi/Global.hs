module Blaze.UI.Db.Poi.Global
  ( module Blaze.UI.Db.Poi.Global
  ) where

import Blaze.UI.Prelude hiding ((:*:), Selector)

import Blaze.UI.Types.Db as Exports hiding (cfg)
import Database.Selda
import Data.Time.Clock (getCurrentTime)
import Blaze.UI.Types.Poi (Poi(Poi), poiTable)
import Blaze.UI.Types.Db.Bytes ()
import Blaze.UI.Types.BinaryHash (BinaryHash)


saveNew
  :: MonadDb m
  => BinaryHash
  -> Address
  -> Bytes
  -> Maybe Text
  -> Maybe Text
  -> m ()
saveNew binHash funcAddr instrOffset poiName poiDescription = withDb $ do
  pid <- liftIO randomIO
  utc <- liftIO getCurrentTime
  insert_ poiTable
    [ Poi
      pid
      Nothing
      Nothing
      binHash
      utc
      funcAddr
      (funcAddr + fromIntegral instrOffset)
      poiName
      poiDescription
      True
    ]

getPoisOfBinary :: MonadDb m => BinaryHash -> m [Poi]
getPoisOfBinary binHash = withDb . query $ do
    poi <- select poiTable
    restrict $ poi ! #binaryHash .== literal binHash
           .&& poi ! #isGlobalPoi .== literal True
    return poi
