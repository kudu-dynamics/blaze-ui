module Blaze.Socket where

import Prelude

import Control.Alternative as Alt
import Control.Monad.Except (runExcept)
import Data.Either (either)
import Data.Maybe (Maybe(..))
import Data.Traversable (for_)
import Effect (Effect)
import Foreign (F, Foreign, readString, unsafeToForeign)
import Web.Event.EventTarget (addEventListener, eventListener)
import Web.Socket.Event.EventTypes as WSET
import Web.Socket.Event.MessageEvent as ME
import Web.Socket.WebSocket (WebSocket)
import Web.Socket.WebSocket as WS

readHelper :: forall a b. (Foreign -> F a) -> b -> Maybe a
readHelper read =
  either (const Nothing) Just <<< runExcept <<< read <<< unsafeToForeign

-- addListener :: WebSocket -> (ServerToWeb -> Effect Unit) -> Effect Unit
-- addListener conn f = do
--   listener <- eventListener $ \ev -> do
--     for_ (ME.fromEvent ev) \msgEvent -> do
--       for_ (readHelper readString (ME.data_ msgEvent)) \strMsg ->
--         for_ (Argo.genericDecodeAeson ArgoOpt.defaultOptions $ Argo.fromString strMsg) \msg ->
--         f msg
--   addEventListener WSET.onMessage listener false (WS.toEventTarget conn)

