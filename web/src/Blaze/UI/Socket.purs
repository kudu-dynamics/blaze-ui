module Blaze.Socket where

import Prelude

import Control.Alternative as Alt
import Control.Monad.Except (runExcept)
import Data.Array as Array
import Data.Either (Either(..), either)
import Data.Maybe (Maybe(..), maybe)
import Data.Traversable (for_)
import Effect (Effect)
import Effect.AVar (AVar)
import Effect.AVar as AVar
import Effect.Aff (Aff, Fiber, effectCanceler, forkAff, makeAff)
import Effect.Aff.AVar as AVarAff
import Effect.Class (liftEffect)
import Effect.Console (log)
import Foreign (F, Foreign, readString, unsafeToForeign)
import Foreign.Class (class Decode, class Encode)
import Foreign.Generic (decodeJSON, encodeJSON)
import Web.Event.EventTarget (addEventListener, eventListener, removeEventListener)
import Web.Socket.Event.EventTypes as WSET
import Web.Socket.Event.MessageEvent as ME
import Web.Socket.ReadyState as RS
import Web.Socket.WebSocket (WebSocket)
import Web.Socket.WebSocket as WS

newtype Conn inMsg outMsg =
  Conn { webSocket :: WebSocket
       , outbox :: AVar outMsg
       , outboxHandlerFiber :: Fiber (Array outMsg)
       }


readHelper :: forall a b. (Foreign -> F a) -> b -> Maybe a
readHelper read =
  either (const Nothing) Just <<< runExcept <<< read <<< unsafeToForeign

-- | Adds a listener for whatever incoming message type the conn has.
-- | the return result is an effect to cancel the event listener.
subscribe :: forall inMsg outMsg. Decode inMsg
             => Conn inMsg outMsg
             -> (inMsg -> Effect Unit)
             -> Effect (Effect Unit)
subscribe (Conn {webSocket}) f = do
  listener <- eventListener $ \ev -> do
    for_ (ME.fromEvent ev) \msgEvent -> do
      for_ (readHelper readString (ME.data_ msgEvent)) \msgStr -> do
        case runExcept (decodeJSON msgStr) of
          Left errs -> do
            log $ "Failed to decode: " <> msgStr
            log $ show errs
          Right msg -> f msg
  addEventListener WSET.onMessage listener false (WS.toEventTarget webSocket)
  pure $ removeEventListener WSET.onMessage listener false (WS.toEventTarget webSocket)


getMessage :: forall inMsg outMsg. Decode inMsg
              => Conn inMsg outMsg
              -> Aff inMsg
getMessage conn = makeAff $ \yield -> do
  canceler <- subscribe conn $ yield <<< Right
  pure $ effectCanceler canceler

-- | Listens for messages until filter returns `Just a`
getMessageWith :: forall inMsg outMsg a. Decode inMsg
                  => Conn inMsg outMsg
                  -> (inMsg -> Maybe a)
                  -> Aff a
getMessageWith conn f = do
  msg <- getMessage conn
  maybe (getMessageWith conn f) pure $ f msg

-- | this will modify the AVar when it gets a chance
modifyAVar :: forall a. AVar a -> (a -> a) -> Effect Unit
modifyAVar av f = do
  void <<< AVar.take av $ \er -> case er of
    Left _ -> pure unit
    Right x -> void $ AVar.put (f x) av (const $ pure unit)

-- | adds message to outbox
sendMessage :: forall inMsg outMsg. Conn inMsg outMsg -> outMsg -> Effect Unit
sendMessage (Conn {outbox}) msg = void $ AVar.put msg outbox $ \_ -> pure unit

-- | this only fires at the first connection, so if you miss it, oh well..
-- | todo: make an aff that checks the ReadyState
waitUntilConnected :: WebSocket -> Aff Unit
waitUntilConnected webSocket = do
  rs <- liftEffect $ WS.readyState webSocket
  case rs of
    RS.Open -> pure unit
    _ ->
      makeAff \yield -> do
        listener <- eventListener $ \_ -> yield (Right unit)
        addEventListener WSET.onOpen listener false (WS.toEventTarget webSocket)
        pure <<< effectCanceler $ do
          removeEventListener WSET.onOpen listener false (WS.toEventTarget webSocket)
  



-- | creates connection, starts outbox listener
-- | TODO: handle disconnect and reconnects
create :: forall inMsg outMsg. Encode outMsg
          => String
          -> Array WS.Protocol
          -> Aff (Conn inMsg outMsg)
create uri protocols = do
  webSocket <- liftEffect $ WS.create uri protocols
  outbox <- liftEffect $ AVar.empty
  outboxHandlerFiber <- forkAff $ outboxHandler webSocket outbox
  let conn = Conn {webSocket, outbox, outboxHandlerFiber}
  pure conn
  where
    outboxHandler webSocket outbox = do
      waitUntilConnected webSocket
      msg <- AVarAff.take outbox
      liftEffect $ WS.sendString webSocket (encodeJSON msg)
      liftEffect $ log $ "Sent: " <> encodeJSON msg
      outboxHandler webSocket outbox -- apparently Aff is stack safe
        
  
  
-- addListener :: WebSocket -> (ServerToWeb -> Effect Unit) -> Effect Unit
-- addListener conn f = do
--   listener <- eventListener $ \ev -> do
--     for_ (ME.fromEvent ev) \msgEvent -> do
--       for_ (readHelper readString (ME.data_ msgEvent)) \strMsg ->
--         for_ (Argo.genericDecodeAeson ArgoOpt.defaultOptions $ Argo.fromString strMsg) \msg ->
--         f msg
--   addEventListener WSET.onMessage listener false (WS.toEventTarget conn)

