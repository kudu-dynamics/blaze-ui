module Blaze.UI.Db.Poi
  ( module Blaze.UI.Db.Poi
  ) where

import Blaze.UI.Prelude hiding ((:*:), Selector)

import Blaze.UI.Types.Db as Exports hiding (cfg)
import Database.Selda
import Data.Time.Clock (getCurrentTime)
import Blaze.UI.Types.HostBinaryPath (HostBinaryPath)
import Blaze.UI.Types.Session (ClientId)
import Blaze.UI.Types.Poi (Poi(Poi), PoiId, poiTable)
import Blaze.UI.Types.BinaryHash (BinaryHash)


-- | use `saveNewCfgAndBranch`
saveNew
  :: MonadDb m
  => ClientId
  -> HostBinaryPath
  -> BinaryHash
  -> Address
  -> Address
  -> Maybe Text
  -> Maybe Text
  -> m ()
saveNew cid hpath binHash funcAddr instrAddr poiName poiDescription = withDb $ do
  pid <- liftIO randomIO
  utc <- liftIO getCurrentTime
  insert_ poiTable
    [ Poi
      pid
      (Just cid)
      (Just hpath)
      binHash
      utc
      funcAddr
      instrAddr
      poiName
      poiDescription
      False
    ]

delete :: MonadDb m => PoiId -> m ()
delete pid = withDb $
  deleteFrom_ poiTable
    (\poi -> poi ! #poiId .== literal pid)

setName :: MonadDb m => PoiId -> Maybe Text -> m ()
setName pid mname = withDb $ do
  update_ poiTable
    (\poi -> poi ! #poiId .== literal pid)
    (\poi -> poi `with` [ #name := literal mname])

setDescription :: MonadDb m => PoiId -> Maybe Text -> m ()
setDescription pid mdescription = withDb $ do
  update_ poiTable
    (\poi -> poi ! #poiId .== literal pid)
    (\poi -> poi `with` [ #description := literal mdescription])

getPoisOfBinary :: MonadDb m => ClientId -> HostBinaryPath -> m [Poi]
getPoisOfBinary cid hpath = withDb . query $ do
    poi <- select poiTable
    restrict ( poi ! #clientId .== literal (Just cid)
               .&& poi ! #hostBinaryPath .== literal (Just hpath)
             )
    return poi

getPoi :: MonadDb m => PoiId -> m (Maybe Poi)
getPoi pid = withDb $ do
  fmap onlyOne . query $ do
    poi <- select poiTable
    restrict (poi ! #poiId .== literal pid)
    return poi
