module Blaze.UI.Db.Poi.Global
  ( module Blaze.UI.Db.Poi.Global
  ) where

import Blaze.UI.Prelude hiding ((:*:), Selector)

import Blaze.UI.Types.Db as Exports hiding (cfg)
import Database.Selda
import Data.Time.Clock (getCurrentTime)
import Blaze.UI.Types.Poi (GlobalPoi(GlobalPoi), GlobalPoiId, globalPoiTable)
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
  insert_ globalPoiTable
    [ GlobalPoi
      pid
      binHash
      utc
      funcAddr
      instrOffset
      poiName
      poiDescription
    ]

delete :: MonadDb m => GlobalPoiId -> m ()
delete pid = withDb $
  deleteFrom_ globalPoiTable
    (\poi -> poi ! #globalPoiId .== literal pid)

setName :: MonadDb m => GlobalPoiId -> Maybe Text -> m ()
setName pid mname = withDb $ do
  update_ globalPoiTable
    (\poi -> poi ! #globalPoiId .== literal pid)
    (\poi -> poi `with` [ #name := literal mname])

setDescription :: MonadDb m => GlobalPoiId -> Maybe Text -> m ()
setDescription pid mdescription = withDb $ do
  update_ globalPoiTable
    (\poi -> poi ! #globalPoiId .== literal pid)
    (\poi -> poi `with` [ #description := literal mdescription])

getPoisOfBinary :: MonadDb m => BinaryHash -> m [GlobalPoi]
getPoisOfBinary binHash = withDb . query $ do
    poi <- select globalPoiTable
    restrict $ poi ! #binaryHash .== literal binHash
    return poi

getPoi :: MonadDb m => GlobalPoiId -> m (Maybe GlobalPoi)
getPoi pid = withDb $ do
  fmap onlyOne . query $ do
    poi <- select globalPoiTable
    restrict $ poi ! #globalPoiId .== literal pid
    return poi
