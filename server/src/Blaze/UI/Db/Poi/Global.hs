module Blaze.UI.Db.Poi.Global
  ( module Blaze.UI.Db.Poi.Global
  ) where

import Blaze.UI.Prelude hiding ((:*:), Selector)

import Blaze.UI.Types.Db as Exports hiding (cfg)
import Database.Selda
import Data.Time.Clock (getCurrentTime)
import Blaze.UI.Types.Poi (Poi(Poi), poiTable)
import Blaze.UI.Types.BinaryHash (BinaryHash)

poiExists
  :: MonadDb m
  => BinaryHash
  -> Address
  -> Bytes
  -> Maybe Text
  -> Maybe Text
  -> m Bool
poiExists binHash funcAddr instrOffset poiName poiDescription = fmap (not . null) . withDb . query $ do
  poi <- select poiTable
  restrict $ poi ! #binaryHash .== literal binHash
         .&& poi ! #isGlobalPoi .== literal True
         .&& poi ! #funcAddr .== literal funcAddr
         .&& poi ! #instrAddr .== literal (funcAddr + fromIntegral instrOffset)
         .&& poi ! #name .== literal poiName
         .&& poi ! #description .== literal poiDescription
         .&& poi ! #isGlobalPoi .== literal True
  return poi

saveNew
  :: MonadDb m
  => BinaryHash
  -> Address
  -> Bytes
  -> Maybe Text
  -> Maybe Text
  -> m ()
saveNew binHash funcAddr instrOffset poiName poiDescription = do
  exists <- poiExists binHash funcAddr instrOffset poiName poiDescription
  unless exists . withDb $ do
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
