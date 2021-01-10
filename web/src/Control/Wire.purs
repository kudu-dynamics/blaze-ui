module Control.Wire where

import Prelude

import Control.Alternative as Alt
import Control.Monad.Except (runExcept)
import Data.Array as Array
import Data.Either (Either(..), either)
import Data.Function.Uncurried (Fn2, runFn2)
import Data.Map (Map)
import Data.Map as Map
import Data.Maybe (Maybe(..), maybe)
import Data.Time.Duration (Milliseconds(..))
import Data.Traversable (for_)
import Data.UUID (UUID, genUUID)
import Data.UUID as UUID
import Effect (Effect)
import Effect.AVar (AVar)
import Effect.Aff (Aff, Fiber, delay, effectCanceler, forkAff, makeAff)
import Effect.Aff.AVar as AVarAff
import Effect.Aff.Class (class MonadAff, liftAff)
import Effect.Class (class MonadEffect, liftEffect)
import Effect.Console (log)
import Effect.Random (random, randomInt)
import Foreign (F, Foreign, readString, unsafeFromForeign, unsafeToForeign)
import Foreign.Class (class Decode, class Encode)
import Foreign.Generic (decodeJSON, encodeJSON)
import Web.DOM.Document as Document
import Web.Event.CustomEvent (CustomEvent)
import Web.Event.CustomEvent as CustomEvent
import Web.Event.Event (Event, EventType(..))
import Web.Event.EventTarget (EventTarget, addEventListener, dispatchEvent, eventListener, removeEventListener)
import Web.HTML (window)
import Web.HTML.HTMLDocument as HTMLDoc
import Web.HTML.Window (document)
import Web.Socket.Event.EventTypes as WSET
import Web.Socket.Event.MessageEvent as ME
import Web.Socket.ReadyState as RS
import Web.Socket.WebSocket (WebSocket)
import Web.Socket.WebSocket as WS
import Effect.AVar as Effect.AVar
import Effect.Aff.AVar as AVar

foreign import customEvent :: CustomEvent

foreign import mkCustomEvent :: Fn2 String Foreign CustomEvent

foreign import getCustomEventData :: Event -> Foreign

newtype SubId = SubId UUID
derive instance eqSubId :: Eq SubId
derive instance ordSubId :: Ord SubId

instance showSubId :: Show SubId where
  show (SubId uuid) = show uuid

data Wire msg = Wire
                { id :: String
                , target :: EventTarget
                , subs :: AVar (Map SubId (AVar msg))
                }


new :: forall m msg. MonadEffect m => m (Wire msg)
new = do
  uuid <- liftEffect genUUID
  dt <- getDocTarget
  v <- liftEffect $ Effect.AVar.new Map.empty
  pure $ Wire { id: UUID.toString uuid
              , target: dt
              , subs: v
              }

dispatch :: forall msg. Wire msg -> msg -> Aff Unit
dispatch (Wire wire) msg = do
  -- liftEffect $ log "sending msg"
  _ <- liftEffect $ Effect.AVar.read wire.subs writeToSubs
  -- liftEffect $ log "sent messages"
  pure unit
  where
    writeToSubs (Left _) = pure unit
    writeToSubs (Right subs) = for_ subs $ \subVar -> do
      -- liftEffect $ log "dispatch: sending to subVar"
      void $ Effect.AVar.put msg subVar $ \_ -> do
        -- liftEffect $ log "dispatch: wrote to subVar"
        pure unit

-- | Listen for just one message
--listen :: forall m msg. MonadAff m => MonadEffect m => Wire msg -> m msg
listen :: forall msg. Wire msg -> Aff msg
listen wire = do
  -- liftEffect $ log "listen: Listening"
  sid <- newSub wire
  -- liftEffect $ log "listen: newsub ++++++++++"
  msg <- listenSub wire sid
  liftEffect $ log "listen: got message"
  deleteSub wire sid
  -- liftEffect $ log "listen: delete sub"
  pure msg
  
listenFor :: forall m msg a. MonadAff m => Wire msg -> (msg -> Maybe a) -> m a
listenFor wire p = do
  sid <- newSub wire
  x <- listenLoop sid
  deleteSub wire sid
  pure x
  where
    listenLoop sid = do
      msg <- listenSub wire sid
      maybe (listenLoop sid) pure $ p msg
  

  --   liftEffect $ log "ADDING EVENT LISTENER++++++"
--   uuid <- liftEffect genUUID
--   liftAff $ do
    
--     listenLoop uuid
--   where
--     listenLoop uuid = do
      
    
--     subs <- Aff.take wire.subs

--     makeAff $ \yield -> do
--     subs <- 
--     listener <- liftEffect <<< eventListener $ \event -> do
--       log $ "Got event"
--       yield (Right <<< unsafeFromForeign $ getCustomEventData event)
--       log $ "Yielded event"
--     addEventListener et listener false target
--     pure <<< effectCanceler $ do
--       log "REMOVING EVENT LISTENER------"
--       removeEventListener et listener false target
--   liftEffect $ log "---------- Got a message! ------------"
--   pure x
--   where
--     et = EventType wid


-- dispatch :: forall m msg. MonadEffect m => Wire msg -> msg -> m Unit
-- dispatch (Wire wid target) msg = do
--   liftEffect $ log "sending event"
--   let event = runFn2 mkCustomEvent wid $ unsafeToForeign msg
--   void <<< liftEffect $ dispatchEvent (CustomEvent.toEvent event) target
--   pure unit



-- listen :: forall m msg. MonadAff m => MonadEffect m => Wire msg -> m msg
-- listen (Wire wid target) = do
--   liftEffect $ log "ADDING EVENT LISTENER++++++"
--   x <- liftAff <<< makeAff $ \yield -> do
--     listener <- liftEffect <<< eventListener $ \event -> do
--       log $ "Got event"
--       yield (Right <<< unsafeFromForeign $ getCustomEventData event)
--       log $ "Yielded event"
--     addEventListener et listener false target
--     pure <<< effectCanceler $ do
--       log "REMOVING EVENT LISTENER------"
--       removeEventListener et listener false target
--   liftEffect $ log "---------- Got a message! ------------"
--   pure x
--   where
--     et = EventType wid

newSub :: forall m msg. MonadEffect m => MonadAff m => Wire msg -> m SubId
newSub (Wire wire) = liftAff $ do
  v <- AVar.empty
  sid <- SubId <$> liftEffect genUUID
  -- liftEffect <<< log $ "newSub: taking subs"
  subs <- AVar.take wire.subs
  -- liftEffect <<< log $ "newSub: got subs"
  AVar.put (Map.insert sid v subs) wire.subs
  -- liftEffect <<< log $ "newSub: created sub: " <> show sid
  pure sid

deleteSub :: forall m msg. MonadEffect m => MonadAff m => Wire msg -> SubId -> m Unit
deleteSub (Wire wire) sid = liftAff $ do
  -- liftEffect <<< log $ "deleteSub: 1"
  subs <- AVar.take wire.subs
  -- liftEffect <<< log $ "deleteSub: 2"
  AVar.put (Map.delete sid subs) wire.subs
  -- liftEffect <<< log $ "deleteSub: 3"

listenSub :: forall m msg. MonadEffect m => MonadAff m => Wire msg -> SubId -> m msg
listenSub (Wire wire) sid = liftAff $ do
  subs <- AVar.take wire.subs
  -- liftEffect <<< log $ "listenSub: got subs"  
  v <- case Map.lookup sid subs of
    Nothing -> do
      -- liftEffect <<< log $ "listenSub: Nothingr"
      v <- AVar.empty
      AVar.put (Map.insert sid v subs) wire.subs
      pure v
    Just v -> do
      -- liftEffect <<< log $ "listenSub: found sid"  
      AVar.put subs wire.subs
      -- liftEffect <<< log $ "listenSub: put subs back"  
      pure v
  AVar.take v


getDocTarget :: forall m. MonadEffect m => m EventTarget
getDocTarget = do
  doc <- liftEffect $ window >>= document
  pure $ Document.toEventTarget (HTMLDoc.toDocument doc)


