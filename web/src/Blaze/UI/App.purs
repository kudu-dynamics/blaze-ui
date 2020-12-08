module Blaze.UI.App where

import Prelude

import Blaze.UI.Types (Nav(NavBinaryView))
import Blaze.UI.Types.WebMessages (ServerToWeb(..), WebToServer(..))
import Control.Alternative as Alt
import Control.Monad.Except (runExcept)
import Data.Either (Either(..), either)
import Data.Generic.Rep (class Generic)
import Data.Generic.Rep.Show (genericShow)
import Data.Interpolate (i)
import Data.Maybe (Maybe(..), fromMaybe)
import Data.Newtype (class Newtype)
import Data.Traversable (for_)
import Data.Tuple.Nested ((/\))
import Effect (Effect)
import Effect.Class (liftEffect)
import Effect.Console (log)
import Foreign (F, Foreign, MultipleErrors, readString, unsafeToForeign)
import Foreign.Class (decode)
import Foreign.Generic (aesonSumEncoding, decodeJSON, defaultOptions, encodeJSON, genericDecodeJSON, genericEncode, genericEncodeJSON)
import React.Basic.DOM (button, div_, p_, text)
import React.Basic.DOM as D
import React.Basic.DOM.Events (targetValue)
import React.Basic.Events (handler, handler_, syntheticEvent)
import React.Basic.Hooks (Component, Ref, component, readRef, useEffect, useEffectOnce, useRef, useState, useState', writeRef)
import React.Basic.Hooks as Hooks
import Web.Event.EventTarget (EventListener, EventTarget, addEventListener, eventListener, removeEventListener)
import Web.Socket.Event.EventTypes as WSET
import Web.Socket.Event.MessageEvent as ME
import Web.Socket.WebSocket (WebSocket)
import Web.Socket.WebSocket as WS
import Web.UIEvent.KeyboardEvent as KE
import Web.UIEvent.KeyboardEvent.EventTypes (keydown)


readHelper :: forall a b. (Foreign -> F a) -> b -> Maybe a
readHelper read =
  either (const Nothing) Just <<< runExcept <<< read <<< unsafeToForeign

sendMessage :: WebSocket -> WebToServer -> Effect Unit
sendMessage conn msg = WS.sendString conn (encodeJSON msg)

mkApp :: WebSocket -> Component {}
mkApp conn = do
  component "App" \_ -> Hooks.do
    nav /\ setNav <- useState' NavBinaryView
    socketMsg /\ setSocketMsg <- useState' SWNoop

    -- set up websocket listener
    useEffectOnce $ do
      listener <- eventListener $ \ev -> do
        for_ (ME.fromEvent ev) \msgEvent -> do
          for_ (readHelper readString (ME.data_ msgEvent)) \msgStr -> do
            case runExcept (decodeJSON msgStr) of
              Left errs -> do
                log $ "Failed to decode: " <> msgStr
                log $ show errs
              Right msg -> setSocketMsg msg

      addEventListener WSET.onMessage listener false (WS.toEventTarget conn)
      pure $ removeEventListener WSET.onMessage listener false (WS.toEventTarget conn)

    msgToServer /\ setMsgToServer <- useState' ""

    pure do
      div_
        [ text $ "hi"
        , p_ [ text $ "From Server: " <> show socketMsg ]
        , D.input { placeholder: "your message"
                  , value: msgToServer
                  , onChange: handler targetValue \mval -> do
                    setMsgToServer <<< fromMaybe "" $ mval
                  }          
        , D.button { onClick: handler_ $ do
                     sendMessage conn $ WSTextMessage { message: msgToServer }
                     log $ "Sent: " <> msgToServer
                   , children: [ D.text "Send" ]
                   }

        , D.div_
          [ D.button { onClick: handler_ $ do
                          sendMessage conn $ WSGetFunctionsList
                          log $ "Requested function list"
                     , children: [ D.text "Get Functions List" ]
                     }
          ]
        ]
