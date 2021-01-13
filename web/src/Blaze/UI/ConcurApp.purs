module Blaze.UI.ConcurApp where

import Data.Monoid
import Prelude

import Blaze.Types.CallGraph (_Function)
import Blaze.Types.CallGraph as CG
import Blaze.UI.App (mkHello)
import Blaze.UI.Components.FunctionView (functionView)
import Blaze.UI.Socket (Conn(..))
import Blaze.UI.Socket as Socket
import Blaze.UI.Types (Nav(..))
import Blaze.UI.Types.WebMessages (ServerToWeb(..), WebToServer(..), _SWFunctionTypeReport, _SWFunctionsList)
import Concur.Core (Widget)
import Concur.Core.Types (affAction, pulse)
import Concur.MaterialUI as M
import Concur.React (HTML, componentClass, renderComponent)
import Concur.React.DOM (div_, h2_, hr', text)
import Concur.React.DOM as D
import Concur.React.Props (ReactProps)
import Concur.React.Props as P
import Concur.React.Run (runWidgetInDom)
import Control.Alt ((<|>))
import Control.Monad.Rec.Class (forever)
import Control.Monad.State.Class (get, put)
import Control.Monad.State.Trans (StateT, runStateT)
import Control.MultiAlternative (orr)
import Control.Wire as Wire
import Data.Array as Array
import Data.BinaryAnalysis (Address(..), Bytes(..))
import Data.Int as Int
import Data.Lens ((^.), (^?))
import Data.Maybe (Maybe(..), fromJust, fromMaybe, maybe)
import Data.String (Pattern(..))
import Data.String as String
import Data.Traversable (traverse)
import Effect (Effect)
import Effect.Aff (Milliseconds(..), delay, forkAff)
import Effect.Aff.Class (liftAff)
import Effect.Class (liftEffect)
import Effect.Class.Console (log)
import Effect.Random (random)
import Pipes.Prelude (mapM)
import React (ReactClass)
import React.Basic.Hooks as Hooks

data Msg = Up | Down

instance showMsg :: Show Msg where
  show Up = "Up"
  show Down = "Down"

prop :: forall a b. String -> a -> ReactProps b
prop = P.unsafeMkProp

tabletest :: Widget HTML Unit
tabletest =
  D.div [ P.style { backgroundColor: "#eeeeee"
                  , padding: "10px"
                  , width: "60%"
                  }
        ]
  [ D.text "here"
  , M.list []
    [ M.listItem [ prop "button" true ]
      [ M.listItemIcon [] [ M.button [ prop "variant" "contained" ] [D.text "X"] ]
      , M.listItemText [ prop "primary" "" ] []
      , M.listItemSecondaryAction [] [ M.button [] [ D.text "X" ] ]
      ]
    , M.listItem [ prop "button" true ]
      [ M.listItemIcon [] [ D.text "Y" ]
      , M.listItemText [ prop "primary" "Pete" ] []
      , M.listItemSecondaryAction [] [ M.button [] [ D.text "X" ] ]
      ]
    ]
  ]


app2 :: Widget HTML Unit
app2 = do
  w <- liftEffect Wire.new
  tabletest
  void $ control w <|> (recvWrapper w 10) <|> (recvWrapper w 20) -- <|> recv w 20 <|> recv w 30
  D.text "Done"
  where
    control w = do
      action <- (Up <$ M.button
                 [ P.onClick
                 , prop "color" "secondary"
                 , prop "variant" "contained"
                 ]
                 [D.text "Up"])
                <|> (Down <$ D.button [P.onClick] [D.text "Down"])
      affAction [] $ Wire.dispatch w action
      control w

    recv w n = do
      msg <- liftAff $ Wire.listen w
      log $ show msg
      case msg of
        Up -> D.text $ show msg
        Down -> D.text $ show msg

    recvWrapper w n = D.div' [ D.text "|"
                             , recv w n
                             ]

    -- recv w n = do
    --   action <- orr
    --             [ D.div' [D.text (show n)]
    --             , do
    --                  pulse
    --                  msg <- affAction [] $ do
    --                    msg <- Wire.listen w
    --                    liftEffect $ log "GOT IT"
    --                    -- ms <- (_ * 30.0) <$> liftEffect random
    --                    -- delay $ Milliseconds ms
    --                    pure msg
    --                  liftEffect $ log "Only once"
    --                  pure msg
    --             ]
    --   log "Got action"
    --   -- case action of
    --   --   Up -> D.text "Up"
    --   --   Down -> D.text "Down"
    --   case action of
    --     Up -> recv w (n + 1)
    --     Down -> recv w (n - 1)

showHex :: Int -> String
showHex = ("0x" <> _) <<< Int.toStringAs Int.hexadecimal

showAddress :: Address -> String
showAddress (Address (Bytes n)) = showHex n

data FuncListAction = FuncListSelect CG.Function
                    | FuncListFilter String

funcItem :: Conn ServerToWeb WebToServer
         -> CG.Function
         -> Widget HTML FuncListAction
funcItem conn x@(CG.Function func) = do
  M.listItem [ prop "button" true ]
    [ M.listItemText
      [ prop "primary" $ func.name
      , prop "secondary" $ showAddress func.address
      , FuncListSelect x <$ P.onClick
      ] []

  -- , M.listItemSecondaryAction []
  --   [ M.button [ -- prop "variant" "contained"
  --              ]
  --     [ D.text "Type Report" ]
  --   ]
  ]

funcList :: Conn ServerToWeb WebToServer
         -> Array CG.Function
         -> Widget HTML CG.Function
funcList conn funcs = go Nothing
  where
    go mFilterText = do
      let filteredFuncs = flip (maybe funcs) mFilterText $ \t ->
            Array.filter
            (\fn -> String.contains (Pattern t) (fn ^. _Function).name)
            funcs
      r <- D.div [ P.style { backgroundColor: "#f5f5f5"
                           , padding: "10px"
                           , width: "40%"
                           }
                 ]
           [ D.div [] [ D.text $ show mFilterText ]
           , M.list [ prop "subheader" $ renderComponent title
                    , prop "dense" true
                    ]
             $ [searchBar $ fromMaybe "" mFilterText]
             <> (funcItem conn <$> filteredFuncs)
           ]
      case r of
        FuncListSelect func -> pure func
        FuncListFilter txt -> go (Just txt)

    searchBar txt =
      D.div []
      [ M.textField [ prop "label" "Search Functions"
                    , prop "variant" "outlined"
                    , prop "fullWidth" true
                    , prop "defaultValue" txt
                    , FuncListFilter <<< P.unsafeTargetValue <$> P.onChange
                    ]
        []
      ]
    title :: forall a. Widget HTML a
    title = M.listSubheader
      [ prop "color" "primary"
      , prop "component" "div"
      , prop "disableSticky" true
      ]
      [ D.text "Functions List" ]

  

app :: Conn ServerToWeb WebToServer -> Widget HTML Unit
app conn = do
  
  liftEffect $ Socket.sendMessage conn WSGetFunctionsList
  funcs <- orr
           [ D.text "loading function list..."
           , liftAff $ Socket.getMessageWith conn (_ ^? _SWFunctionsList)
           ]
  selectedFunc <- funcList conn funcs
  functionView conn selectedFunc
  D.text $ show selectedFunc
  -- where
  --   send = do
  --     void $ D.button [P.onClick] [D.text "Send a message"]
  --     liftEffect <<< Socket.sendMessage conn $ WSTextMessage "Hello chum bag"
  --     send


messageTime :: forall a. Conn ServerToWeb WebToServer -> Widget HTML a
messageTime conn = do
  -- liftEffect <<< Socket.sendMessage conn $ WSTextMessage "Hello chum bag"
  msg <- liftAff $ Socket.getMessage conn
  log $ show msg
  D.text $ show msg
  --messageTime conn

helloWidgetS :: forall a. StateT Int (Widget HTML) a
helloWidgetS = forever do
  count <- get
  void $ D.div' [ D.button [P.onClick] [D.text ("For the " <> show count <> " time, hello sailor!")] ]
  put (count + 1)

-- Widgety Widget
data View = View Int HTML

main :: Conn ServerToWeb WebToServer -> Effect Unit
main conn = do
    runWidgetInDom "main" $ orr
      [ div_ [] $ app conn
--      , div_ [] app2
      ]
  -- where
  --   widget w s = orr
  --     [ hr'
  --     , h2_ [] $ text s
  --     , div_ [] (w conn)
  --     ]
