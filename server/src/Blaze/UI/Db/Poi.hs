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


-- | use `saveNewCfgAndBranch`
saveNew :: MonadDb m
  => ClientId
  -> HostBinaryPath
  -> Address
  -> Address
  -> Maybe Text
  -> Maybe Text
  -> m ()
saveNew cid hpath funcAddr instrAddr poiName poiDescription = withDb $ do
  pid <- liftIO randomIO
  utc <- liftIO getCurrentTime
  insert_ poiTable
    [ Poi
      pid
      cid
      hpath
      utc
      funcAddr
      instrAddr
      poiName
      poiDescription
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
    (\poi -> poi `with` [ #name := literal mdescription])

getPoisOfBinary :: MonadDb m => ClientId -> HostBinaryPath -> m [Poi]
getPoisOfBinary cid hpath = withDb . query $ do
    poi <- select poiTable
    restrict ( poi ! #clientId .== literal cid
               .&& poi ! #hostBinaryPath .== literal hpath
             )
    return poi

