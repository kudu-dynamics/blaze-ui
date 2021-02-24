module Blaze.UI.Components.TabView where

import Blaze.UI.Prelude
import Prelude

import Blaze.Types.CallGraph as CG
import Blaze.UI.Socket (Conn(..))
import Blaze.UI.Socket as Socket
import Blaze.UI.Types.WebMessages (ServerToWeb(..), WebToServer(..))
import Concur.Core (Widget)
import Concur.Core.FRP (Signal, display, dyn, loopW)
import Concur.React (HTML)
import Concur.React.DOM as D
import Concur.React.Props as P
import Control.Alt ((<|>))
import Control.MultiAlternative (orr)
import Data.Maybe (Maybe(..))
import Data.Traversable (traverse)
import Effect.Aff.Class (liftAff)
import Effect.Class (liftEffect)
import Effect.Class.Console (log)

type Tab = { name :: String
           , view :: Widget HTML Unit
           }

renderTab :: Boolean
          -> String
          -> Widget HTML String
renderTab selected label = do
  D.span [ P.className "tab-label"
         , P.onClick $> label
         ]
    [D.text $ label
     <> if selected then "_" else ""
    ]

tabsHeader :: Array String
           -> String
           -> Widget HTML String
tabsHeader labels selectedLabel =
  D.div [] $ (\lbl -> renderTab (lbl == selectedLabel) lbl) <$> labels

inf :: forall a. Widget HTML Unit
         -> Widget HTML a
inf w = do
  w
  log "hey there"
  inf w

wrapView :: Tab
         -> Boolean
         -> Signal HTML Unit
wrapView tab isSelected = do
  D.div_ [] -- [ P.style { "display": if isSelected then "block" else "none" }]
    $ display (inf tab.view)


tabbedView :: Tab
           -> Array Tab
           -> Widget HTML Unit
tabbedView initialTab tabs = dyn $ do
  selected <- loopW initialTab.name $ \selectedLabel -> tabsHeader labels selectedLabel
  void $ traverse (\tab -> wrapView tab (selected == tab.name)) tabs
  where
    labels = (_.name) <$> tabs
