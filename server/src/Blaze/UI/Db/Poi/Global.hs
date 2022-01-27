module Blaze.UI.Db.Poi.Global
  ( module Blaze.UI.Db.Poi.Global
  ) where

import Blaze.UI.Prelude hiding ((:*:), Selector)

import Blaze.UI.Types.Db as Exports hiding (cfg)
import Database.Selda
import Data.Time.Clock (getCurrentTime)
import Blaze.UI.Types.Poi (Poi(Poi), PoiId, poiTable)
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

-- delete :: MonadDb m => PoiId -> m ()
-- delete pid = withDb $
--   deleteFrom_ poiTable
--     (\poi -> poi ! #poiId .== literal pid)

-- setName :: MonadDb m => PoiId -> Maybe Text -> m ()
-- setName pid mname = withDb $ do
--   update_ poiTable
--     (\poi -> poi ! #poiId .== literal pid)
--     (\poi -> poi `with` [ #name := literal mname])

-- setDescription :: MonadDb m => PoiId -> Maybe Text -> m ()
-- setDescription pid mdescription = withDb $ do
--   update_ poiTable
--     (\poi -> poi ! #poiId .== literal pid)
--     (\poi -> poi `with` [ #description := literal mdescription])

getPoisOfBinary :: MonadDb m => BinaryHash -> m [Poi]
getPoisOfBinary binHash = withDb . query $ do
    poi <- select poiTable
    restrict $ poi ! #binaryHash .== literal binHash
    return poi

-- getPoi :: MonadDb m => PoiId -> m (Maybe Poi)
-- getPoi pid = withDb $ do
--   fmap onlyOne . query $ do
--     poi <- select poiTable
--     restrict $ poi ! #poiId .== literal pid
--     return poi
