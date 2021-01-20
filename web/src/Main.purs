module Main where

import Prelude

import Blaze.UI.Socket (Conn(..))
import Blaze.UI.Socket as Socket
import Blaze.UI.ReactHooksApp (mkApp)
import Blaze.UI.Components.Counter (mkCounter)
import Blaze.UI.App as App
import Blaze.UI.Types.WebMessages (ServerToWeb, WebToServer)
import Concur.Core (Widget)
import Concur.React (HTML)
import Concur.React.DOM as D
import Concur.React.Props as P
import Concur.React.Run (runWidgetInDom)
import Control.Alternative ((<|>))
import Control.Alternative as Alt
import Control.Coroutine as CR
import Control.Coroutine.Aff (emit)
import Control.Coroutine.Aff as CRA
import Control.Monad.Except (runExcept)
import Data.Array (snoc)
import Data.Either (either)
import Data.Foldable (for_)
import Data.Maybe (Maybe(..))
import Data.Tuple.Nested ((/\))
import Effect (Effect)
import Effect.AVar (AVar)
import Effect.AVar as EAVar
import Effect.Aff (Aff, launchAff_)
import Effect.Aff.AVar as AVar
import Effect.Aff.Class (liftAff)
import Effect.Class (class MonadEffect, liftEffect)
import Effect.Console (log)
import Foreign (F, Foreign, unsafeToForeign, readString)
import Halogen as H
import Halogen.Aff as HA
import Halogen.HTML as HH
import Halogen.HTML.Events as HE
import Halogen.HTML.Properties as HP
import Halogen.Hooks as Hooks
import Halogen.VDom.Driver (runUI)
import React.Basic.DOM (render)
import Web.DOM.Document as Document
import Web.DOM.Element as Elem
import Web.DOM.Node (setTextContent, textContent)
import Web.DOM.ParentNode (QuerySelector(..), querySelector)
import Web.Event.Event as Event
import Web.Event.EventTarget as EET
import Web.HTML (window)
import Web.HTML.HTMLDocument (toParentNode)
import Web.HTML.HTMLDocument as HTMLDoc
import Web.HTML.HTMLElement (toElement)
import Web.HTML.Window (document)
import Web.Socket.Event.EventTypes as WSET
import Web.Socket.Event.MessageEvent as ME
import Web.Socket.WebSocket as WS

blazeServerHost :: String
blazeServerHost = "localhost"

blazeServerWsPort :: String
blazeServerWsPort = "31337"

sessionId :: String
sessionId = "L2hvbWUvdGVkZHkva3VkdS9oYXNrZWxsL2hhc2tlbGwtYmxhemUvcmVzL2V4dHJhX2JpbnMvYnJ5YW50L2JyeWFudC5ibmRi"

main :: Effect Unit
main = do
  doc <- window >>= document
  let docTarget = Document.toEventTarget (HTMLDoc.toDocument doc)
  mroot <- querySelector (QuerySelector "#root") (toParentNode doc)
  let wsUri = "ws://" <> blazeServerHost <> ":" <> blazeServerWsPort
              <> "/web/" <> sessionId
  -- conn <- WS.create wsUri []
  case mroot of
    Nothing ->
      log "couldn't find root node"
    Just root -> do
      -- let rootNode = Elem.toNode root
      -- log $ "got root"
      -- t <- textContent rootNode
      -- log t
      -- setTextContent "Billy bob" rootNode
      launchAff_ $ do
        conn <- Socket.create wsUri [] :: Aff (Conn ServerToWeb WebToServer)
        liftEffect $ App.main conn
        -- liftEffect $ do
        --   app <- mkApp conn
        --   render (app {}) root

      -- counter <- mkCounter
      -- render (counter { label : "Bilbo" }) root

  log "What do we do now?"

main' :: Effect Unit
main' = do
  let wsUri = "ws://" <> blazeServerHost <> ":" <> blazeServerWsPort
              <> "/web/" <> sessionId
  connection <- WS.create wsUri []
  v <- EAVar.empty

  runWidgetInDom "main" $ do
    counterWidget v 5
      <|> bilboWidget v
      <|> counterWidget v 0
  HA.runHalogenAff do
    body <- HA.awaitBody
    io <- runUI logComponent unit body

    -- The wsSender consumer subscribes to all output messages
    -- from our component
    io.subscribe $ wsSender connection

    -- Connecting the consumer to the producer initializes both,
    -- feeding queries back to our component as messages are received.
    CR.runProcess (wsProducer connection CR.$$ wsConsumer io.query)


-- A producer coroutine that emits messages that arrive from the websocket.
wsProducer :: WS.WebSocket -> CR.Producer String Aff Unit
wsProducer socket = CRA.produce \emitter -> do
  listener <- EET.eventListener \ev -> do
    for_ (ME.fromEvent ev) \msgEvent ->
      for_ (readHelper readString (ME.data_ msgEvent)) \msg ->
        emit emitter msg
  EET.addEventListener
    WSET.onMessage
    listener
    false
    (WS.toEventTarget socket)
  where
    readHelper :: forall a b. (Foreign -> F a) -> b -> Maybe a
    readHelper read =
      either (const Nothing) Just <<< runExcept <<< read <<< unsafeToForeign

-- A consumer coroutine that takes the `query` function from our component IO
-- record and sends `ReceiveMessage` queries in when it receives inputs from the
-- producer.
wsConsumer :: (forall a. Query a -> Aff (Maybe a)) -> CR.Consumer String Aff Unit
wsConsumer query = CR.consumer \msg -> do
  void $ query $ H.tell $ ReceiveMessage msg
  pure Nothing

-- A consumer coroutine that takes output messages from our component IO
-- and sends them using the websocket
wsSender :: WS.WebSocket -> CR.Consumer Message Aff Unit
wsSender socket = CR.consumer \msg -> do
  case msg of
    OutputMessage msgContents ->
      liftEffect $ WS.sendString socket msgContents
  pure Nothing

data Query a = ReceiveMessage String a

data Message = OutputMessage String

logComponent
  :: forall unusedInput anyMonad
   . MonadEffect anyMonad
  => H.Component HH.HTML Query unusedInput Message anyMonad
logComponent = Hooks.component \rec _ -> Hooks.do
  state /\ stateIdx <- Hooks.useState {inputText: "", messages: []}
  Hooks.useQuery rec.queryToken case _ of
    ReceiveMessage msg next -> do
      let incomingMessage = "Receivedd: " <> msg
      Hooks.modify_ stateIdx (\st -> st { messages = st.messages `snoc` incomingMessage })
      pure $ Just next
  Hooks.pure $
    HH.form
    [ HE.onSubmit \ev -> Just do
        liftEffect $ Event.preventDefault ev
        st <- Hooks.get stateIdx
        let outgoingMessage = st.inputText
        Hooks.raise rec.outputToken $ OutputMessage outgoingMessage
        Hooks.modify_ stateIdx \st' -> st'
          { messages = st'.messages `snoc` ("Sending: " <> outgoingMessage)
          , inputText = ""
          }
    ]
    [ HH.ol_ $ map (\msg -> HH.li_ [ HH.text msg ]) state.messages
    , HH.input
        [ HP.type_ HP.InputText
        , HP.value state.inputText
        , HE.onValueInput \val -> Just do
            Hooks.modify_ stateIdx (_ { inputText = val })
        ]
    , HH.button
        [ HP.type_ HP.ButtonSubmit ]
        [ HH.text "Send Message" ]
    ]


------------------------

counterWidget :: forall a. AVar String -> Int -> Widget HTML a
counterWidget v count = do
  n <- D.div'
        [ D.p' [D.text ("State: " <> show count)]
        , D.button [P.onClick] [D.text "Increment"] $> count+1
        , D.button [P.onClick] [D.text "Decrement"] $> count-1
        , showLatestAVar "nothing yet"
        ]
  liftEffect (log ("COUNT IS NOW: " <> show n))
  counterWidget v n
  where
    showLatestAVar s = do
      s' <- D.text s <|> liftAff (AVar.take v)
      showLatestAVar s'

bilboWidget :: forall a. AVar String -> Widget HTML a
bilboWidget v = do
  s <- D.div'
        [ D.button [P.onClick] [D.text "Say hello"] $> "hello"
        , D.button [P.onClick] [D.text "Say Goodbye"] $> "goodbye"
        ]
  _ <- liftAff $ AVar.tryPut s v
  bilboWidget v
