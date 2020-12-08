module Blaze.UI.Components.Counter where

import Prelude

import Control.Alternative as Alt
import Control.Monad.Except (runExcept)
import Data.Either (either)
import Data.Generic.Rep (class Generic)
import Data.Generic.Rep.Show (genericShow)
import Data.Interpolate (i)
import Data.Maybe (Maybe(..))
import Data.Newtype (class Newtype)
import Data.Traversable (for_)
import Data.Tuple.Nested ((/\))
import Effect (Effect)
import Effect.Class (liftEffect)
import Effect.Console (log)
import Foreign (F, Foreign, unsafeToForeign, readString)
import Foreign.Generic (aesonSumEncoding, defaultOptions, genericDecodeJSON, genericEncode, genericEncodeJSON)
import React.Basic.DOM (button, div_, p_, text)
import React.Basic.Events (handler_)
import React.Basic.Hooks (Component, Ref, component, readRef, useEffect, useEffectOnce, useRef, useState, useState', writeRef)
import React.Basic.Hooks as Hooks
import Web.Event.EventTarget (EventListener, EventTarget, addEventListener, eventListener, removeEventListener)
import Web.Socket.Event.EventTypes as WSET
import Web.Socket.Event.MessageEvent as ME
import Web.Socket.WebSocket (WebSocket)
import Web.Socket.WebSocket as WS
import Web.UIEvent.KeyboardEvent as KE
import Web.UIEvent.KeyboardEvent.EventTypes (keydown)

type Props = { label :: String
             , setTotal :: (Int -> Int) -> Effect Unit
             , totalRef :: Ref Int
             }

mkCounter :: Component Props
mkCounter = component "Counter" \props -> Hooks.do
  count /\ setCount <- useState' 0
  highestCount /\ setHighestCount <- useState' 0
  pure do
    div_
      [ p_ [ text $ i "You clicked " count " times (" highestCount ")" ]
      , button
          { onClick: handler_ $ do
               setCount (count + 1)
               n <- readRef props.totalRef
               let hcount = max n $ count + 1
               writeRef props.totalRef hcount
               setHighestCount hcount
               props.setTotal (_ + 1)
          , children: [ text props.label ]
          }
      ]

readHelper :: forall a b. (Foreign -> F a) -> b -> Maybe a
readHelper read =
  either (const Nothing) Just <<< runExcept <<< read <<< unsafeToForeign

-- data SWLogErrorArgs =
--     SWLogErrorArgs {
--       message :: String
--     }
-- derive instance genericSWLogErrorArgs :: Generic SWLogErrorArgs _
-- -- derive instance newtypeSWLogErrorArgs :: Newtype SWLogErrorArgs _
-- instance showSWLogErrorArgs :: Show SWLogErrorArgs where show = genericShow
-- -- instance encodeSWLogErrorArgs ::
-- instance encodeAesonSWLogErrorArgs :: EncodeJson SWLogErrorArgs where
--   encodeJson = genericEncodeAeson ArgoOpt.defaultOptions
-- instance encodeGenericSWLogErrorArgs :: Encode SWLogErrorArgs where
--   encode = genericEncode defaultOptions

-- data ServerToWeb = SWStringMessage { message :: String }
--                  | SWLogInfo { message :: String }
--                  | SWLogWarn { message :: Maybe String }
--                  | SWLogError { message :: String }
--                  | SWNoop


-- derive instance genericServerToWeb :: Generic ServerToWeb _
-- instance showServerToWeb :: Show ServerToWeb where show = genericShow

mkApp :: EventTarget -> WebSocket -> Component {}
mkApp docTarget conn = do
  ctr1 <- mkCounter
  ctr2 <- mkCounter
  let opts = defaultOptions { unwrapSingleConstructors = true
                            , sumEncoding = aesonSumEncoding
                            , unwrapSingleArguments = true
                            }
  -- log <<< genericEncodeJSON opts $ SWLogWarn { message: "hey there" }
  log <<< genericEncodeJSON opts $ Just 3
  component "App" \_ -> Hooks.do
    total /\ setTotal <- useState 0
    lastKeyDown /\ setLastKeyDown <- useState' ""
    socketMsg /\ setSocketMsg <- useState' ""
    totalRef <- useRef 10

    -- set up websocket listener
    useEffectOnce $ do
      listener <- eventListener $ \ev -> do
        for_ (ME.fromEvent ev) \msgEvent -> do
          for_ (readHelper readString (ME.data_ msgEvent)) \msg ->
            setSocketMsg msg
      addEventListener WSET.onMessage listener false (WS.toEventTarget conn)
      pure $ removeEventListener WSET.onMessage listener false (WS.toEventTarget conn)

    useEffectOnce $ do
      f <- eventListener $ \ev -> do
        for_ (KE.fromEvent ev) \keyEvent -> do
          setLastKeyDown $ KE.key keyEvent
      addEventListener keydown f true docTarget
        
      n <- readRef totalRef
      setTotal (const n)
      pure $ removeEventListener keydown f true docTarget
    pure do
      div_
        [ text $ "hi"
        , case lastKeyDown of
          "k" -> text "My mother loves you!"
          _ -> text ""
        , p_ [ text $ i "From Server: " socketMsg ]
        , p_ [ text $ i "Total Callback: " total ]
        , p_ [ text $ i "Last Key Down: " lastKeyDown ]
        , ctr1 { label: "whatever"
               , setTotal: setTotal
               , totalRef: totalRef
               }
        , ctr2 { label: "jones"
               , setTotal: setTotal
               , totalRef: totalRef
               }
        ]
