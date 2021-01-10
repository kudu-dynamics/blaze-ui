module Blaze.UI.App where

import Prelude

import Blaze.UI.Socket (Conn)
import Blaze.UI.Socket as Socket
import Blaze.Types.CallGraph (_Function)
import Blaze.Types.CallGraph as CG
import Blaze.UI.Types (Nav(..))
import Blaze.UI.Types.WebMessages (ServerToWeb(..), WebToServer(..), _SWFunctionTypeReport)
import Control.Alternative as Alt
import Control.Monad.Except (runExcept)
import Data.Array as Array
import Data.Either (Either(..), either)
import Data.Generic.Rep (class Generic)
import Data.Generic.Rep.Show (genericShow)
import Data.Interpolate (i)
import Data.Lens ((^.), (^?))
import Data.Maybe (Maybe(..), fromMaybe)
import Data.Newtype (class Newtype)
import Data.Traversable (for_)
import Data.Tuple.Nested ((/\))
import Effect (Effect)
import Effect.Aff (Aff, Milliseconds(..), delay, effectCanceler, makeAff)
import Effect.Aff as Aff
import Effect.Class (liftEffect)
import Effect.Console (log)
import Effect.Random (randomInt)
import Foreign (F, Foreign, MultipleErrors, readString, unsafeToForeign)
import Foreign.Class (decode)
import Foreign.Generic (aesonSumEncoding, decodeJSON, defaultOptions, encodeJSON, genericDecodeJSON, genericEncode, genericEncodeJSON)
import React.Basic.DOM (button, div_, p_, text)
import React.Basic.DOM as D
import React.Basic.DOM.Events (targetValue)
import React.Basic.Events (handler, handler_, syntheticEvent)
import React.Basic.Hooks (Component, Ref, component, readRef, useEffect, useEffectOnce, useRef, useState, useState', writeRef)
import React.Basic.Hooks as Hooks
import React.Basic.Hooks.Aff (useAff)
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


mkFunctionView :: Conn ServerToWeb WebToServer
               -> Component { func :: CG.Function }
mkFunctionView conn = do
  component "FunctionView" \props -> Hooks.do
    mreport <- useAff unit $ do
      liftEffect <<< Socket.sendMessage conn $ WSGetTypeReport props.func
      Socket.getMessageWith conn (_ ^? _SWFunctionTypeReport)
      
    pure do
      div_
        [ text $ (props.func ^. _Function).name
        , div_ $ case mreport of
          Nothing -> [ text "loading type report..." ]
          Just tr -> [ text tr ]
        ]


mkFunctionsList :: Conn ServerToWeb WebToServer
                -> Component { setNav :: Nav -> Effect Unit }
mkFunctionsList conn = do
  component "FunctionsList" \props -> Hooks.do
    -- funcs /\ setFuncs <- useState' []

    mmesg <- useAff unit $ do
      liftEffect $ Socket.sendMessage conn WSGetFunctionsList
      waitForFuncListMessage

    pure $ div_
      [ D.div_ [ text "Functions" ]
      , D.div { id: "function-list"
              , className: ""
              , children:
                case mmesg of
                  Nothing -> [ text "loading..." ]
                  Just funcs -> map (funcListItem props.setNav) funcs              
              }
      ]
  where
    waitForFuncListMessage = do
      msg <- Socket.getMessage conn
      case msg of
        SWFunctionsList funcs -> pure funcs
        _ -> waitForFuncListMessage


    funcListItem setNav func = do
      div_
        [ text $ (func ^. _Function).name
        , D.button { onClick: handler_ $ do
                        log $ "ok"
                        setNav $ NavFunctionView func
                   , children: [ D.text "Type Check" ]
                   }

        , D.button { onClick: handler_ $ do
                        log $ "Send a message here..."
                   , children: [ D.text "Goto in Binja" ]
                   }
          
        ]



-- getMessage :: WebSocket -> Aff ServerToWeb
-- getMessage conn = makeAff \yieldResult -> do
--   listener <- eventListener $ \ev -> do
--     for_ (ME.fromEvent ev) \msgEvent -> do
--       for_ (readHelper readString (ME.data_ msgEvent)) \msgStr -> do
--         case runExcept (decodeJSON msgStr) of
--           Left errs -> do
--             log $ "Failed to decode: " <> msgStr
--             log $ show errs
--             yieldResult <<< Left <<< Aff.error $ show errs
--           Right msg -> yieldResult <<< Right $ msg
--   addEventListener WSET.onMessage listener false (WS.toEventTarget conn)
--   pure <<< effectCanceler $ do
--     removeEventListener WSET.onMessage listener false (WS.toEventTarget conn)


mkApp :: Conn ServerToWeb WebToServer -> Component {}
mkApp conn = do
  functionView <- mkFunctionView conn
  functionsList <- mkFunctionsList conn
  -- Socket.sendMessage conn $ WSTestEncoding (BadBoy {one: 7, two: "hey"})
  component "App" \_ -> Hooks.do
    nav /\ setNav <- useState' NavBinaryView
    socketMsg /\ setSocketMsg <- useState' SWNoop

    -- set up websocket listener
    useEffectOnce <<< Socket.subscribe conn $ \msg -> do
      log <<< show $ msg
      setSocketMsg msg

    msgToServer /\ setMsgToServer <- useState' ""

    pure $ case nav of
      NavBinaryView -> do
        div_
          [ text $ "hi"
          , D.input { placeholder: "your message"
                    , value: msgToServer
                    , onChange: handler targetValue \mval -> do
                      setMsgToServer <<< fromMaybe "" $ mval
                    }          
          , D.button { onClick: handler_ $ do
                          Socket.sendMessage conn $ WSTextMessage msgToServer
                          log $ "Sent: " <> msgToServer
                     , children: [ D.text "Send" ]
                     }

          , D.div_
            [ D.button { onClick: handler_ $ do
                            Socket.sendMessage conn $ WSGetFunctionsList
                            log $ "Requested function list"
                       , children: [ D.text "Get Functions List" ]
                       }
            ]
          , functionsList {setNav}
          ]
      NavFunctionView func -> functionView { func }

        
