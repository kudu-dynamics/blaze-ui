module Blaze.UI.App where

import Data.Monoid
import Prelude

import Blaze.Types.CallGraph (_Function)
import Blaze.Types.CallGraph as CG
import Blaze.UI.Components.FunctionView (functionView)
import Blaze.UI.Components.TabView (tabbedView)
import Blaze.UI.Prelude (prop, showHex)
import Blaze.UI.Socket (Conn(..))
import Blaze.UI.Socket as Socket
import Blaze.UI.Types (Nav(..))
import Blaze.UI.Types.WebMessages (ServerToWeb(..), WebToServer(..), _SWFunctionTypeReport, _SWFunctionsList, _SWPilType, _SWProblemType)
import Blaze.UI.Web.Pil (DeepSymType(..), PilType(..))
import Concur.Core (Widget)
import Concur.Core.FRP (Signal, display, dyn, loopS, loopW, step)
import Concur.Core.Types (affAction, pulse)
import Concur.React (HTML, componentClass, renderComponent)
import Concur.React.DOM (div_, h2_, hr', text)
import Concur.React.DOM as D
import Concur.React.MUI.DOM as M
import Concur.React.Props (ReactProps)
import Concur.React.Props as P
import Concur.React.Run (runWidgetInDom)
import Control.Alt ((<|>))
import Control.Monad.Rec.Class (forever)
import Control.Monad.State (modify)
import Control.Monad.State.Class (get, put)
import Control.Monad.State.Trans (StateT, runStateT)
import Control.MultiAlternative (orr)
import Control.Wire as Wire
import Data.Array as Array
import Data.BigInt as BigInt
import Data.BinaryAnalysis (Address(..), Bytes(..))
import Data.Int as Int
import Data.Lens ((^.), (^?))
import Data.Maybe (Maybe(..), fromJust, fromMaybe, maybe)
import Data.String (Pattern(..))
import Data.String as String
import Data.Traversable (traverse)
import Data.Tuple.Nested ((/\), type (/\))
import Effect (Effect)
import Effect.Aff (Milliseconds(..), delay, forkAff)
import Effect.Aff.Class (liftAff)
import Effect.Class (liftEffect)
import Effect.Class.Console (log)
import Effect.Random (random)
import Foreign.Generic (encode, encodeJSON)
import Pipes.Prelude (mapM)
import React (ReactClass)
import React.Basic.Hooks as Hooks

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


-- Showcases a bug where if both children widgets update simultaneously,
-- only one returns result, and the others are stuck in limbo.
-- but the commented out portion, with random return delays, works
-- (as long as the random delays aren't the same)
-- Possible lame fix would be to have slight delay in Wire between writing
-- to each sub
wireTest :: Widget HTML Unit
wireTest = do
  w <- liftEffect Wire.new
  tabletest
  void $ control w <|> (recvWrapper w 10) <|> (recvWrapper w 20) -- <|> recv w 20 <|> recv w 30
  D.text "Done"
  where
    control w = do
      action <- ("Up" <$ M.button
                 [ P.onClick
                 , prop "color" "secondary"
                 , prop "variant" "contained"
                 ]
                 [D.text "Up"])
                <|> ("Down" <$ D.button [P.onClick] [D.text "Down"])
      affAction [] $ Wire.dispatch w action
      control w

    recv w n = do
      msg <- liftAff $ Wire.listen w
      log msg
      D.text msg

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
         -> Maybe String
         -> Widget HTML (Maybe String /\ CG.Function)
funcList conn funcs mFilterText = do
  let filteredFuncs = flip (maybe funcs) mFilterText $ \t ->
        Array.filter
        (\fn -> String.contains (Pattern t) (fn ^. _Function).name)
        funcs
  r <- D.div [ P.style { backgroundColor: "#f5f5f5"
                       , padding: "10px"
                       }
             ]
       [ M.list [ prop "subheader" $ renderComponent title
                , prop "dense" true
                ]
         $ [searchBar $ fromMaybe "" mFilterText]
         <> (funcItem conn <$> filteredFuncs)
       ]
  case r of
    FuncListSelect func -> pure (mFilterText /\ func)
    FuncListFilter txt -> funcList conn funcs (Just txt)

  where
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


tabDemo :: Widget HTML Unit
tabDemo = do
  void $ M.appBar [] 
    [ M.tabs []
      [ M.tab [ P.label "One" ] []
      , M.tab [ P.label "Two" ] []
      , M.tab [ P.label "Three"] []
      ]
    ]

counter :: Boolean -> Int -> Signal HTML Int
counter winner init = loopW init $ \n -> D.div'
  [ n+1 <$ D.button [P.onClick] [D.text "+"]
  , D.span' [D.text (show n)]
  , n-1 <$ D.button [P.onClick] [D.text "-"]
  , if winner then D.text "Winner" else D.text "_"
  ]

counter2 :: Int -> Widget HTML Unit
counter2 n = do
  void $ D.div [] [ D.button [ P.onClick ] [ D.text $ show n ] ]
  counter2 (n + 1)

signalDemo :: Widget HTML Unit
signalDemo = dyn $ loopS (0 /\ 10) $ \(a /\ b) -> do
  display $ D.text (show $ max a b)
  a' <- counter (a > b) a
  b' <- counter (b > a) b
  s <- hello ""
  pure $ a' /\ b'

hello :: String -> Signal HTML String
hello s = step s do
  greeting <- D.div'
    [ "Hello" <$ D.button [P.onClick] [D.text "Say Hello"]
    , "Namaste" <$ D.button [P.onClick] [D.text "Say Namaste"]
    ]
  void $ D.text (greeting <> " Sailor!") <|> D.button [P.onClick] [D.text "restart"]
  pure (hello greeting)

tabDemo2 :: Widget HTML Unit
tabDemo2 = do
  tabbedView a [a, b, c]
  where
    a = { name: "A"
        , view: dyn $ hello "Jim"
        }
    b = { name: "B"
        , view: D.div [P.key "counter"] [counter2 10]
        }
    c = { name: "C"
        , view: D.text "hey there"
        }

app :: Conn ServerToWeb WebToServer -> Widget HTML Unit
app conn = do
  liftEffect $ Socket.sendMessage conn WSGetFunctionsList
  funcs <- orr
           [ D.text "loading function list..."
           , liftAff $ Socket.getMessageWith conn (_ ^? _SWFunctionsList)
           , do
             m <- liftAff $ Socket.getMessageWith conn (_ ^? _SWProblemType)
             log (show m)
             D.text "got it"
           ]
  void $ gridLoop Nothing Nothing funcs
  where
    gridLoop alreadySelectedFunc mFilterText funcs = do
      (mFilterText' /\ selectedFunc) <-
        M.grid [prop "container" true, prop "spacing" 2]
        [ M.grid [ prop "item" true
                 , P.className "func-list-grid-item"
                 ]
          [ funcList conn funcs mFilterText ]
        , M.grid [ prop "item" true
                 , P.className "non-func-list-grid-item"
                 ]
          [ case alreadySelectedFunc of
               Nothing -> D.text "Select a function"
               Just func -> functionView conn func
          ]
        ]
      gridLoop (Just selectedFunc) mFilterText' funcs


main :: Conn ServerToWeb WebToServer -> Effect Unit
main conn = do
  runWidgetInDom "main" $ orr
    [ div_ [] $ app conn
    ]
