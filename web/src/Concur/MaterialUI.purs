module Concur.MaterialUI where

import Prelude

import Concur.React.DOM (El)
import Concur.React.DOM as D
import Effect (Effect)
import Effect.Aff.Compat (EffectFnAff)
import React (Children, ReactClass, unsafeCreateElement)
import React.DOM.Props (unsafeFromPropsArray)
import React.SyntheticEvent as R

foreign import _button :: forall a. ReactClass a

foreign import _buttonGroup :: forall a. ReactClass a

foreign import _textField :: forall a. ReactClass a

foreign import _grid :: forall a. ReactClass a

foreign import _dataGrid :: forall a. ReactClass a

foreign import classList :: forall a. ReactClass a
foreign import classListItem :: forall a. ReactClass a
foreign import classListItemAvatar :: forall a. ReactClass a
foreign import classListItemIcon :: forall a. ReactClass a
foreign import classListItemSecondaryAction :: forall a. ReactClass a
foreign import classListItemText :: forall a. ReactClass a
foreign import classListSubheader :: forall a. ReactClass a

mkEl :: forall trash. ReactClass { children :: Children | trash } -> D.El
mkEl cls = D.el' (unsafeCreateElement cls <<< unsafeFromPropsArray)

mkDom :: forall trash. ReactClass { children :: Children | trash } -> D.El
mkDom = mkEl

button :: D.El
button = mkEl _button

buttonGroup :: D.El
buttonGroup = mkEl _buttonGroup

textField :: D.El
textField = mkEl _textField

grid :: D.El
grid = mkEl _grid

-- dataGrid :: D.El
-- dataGrid = mkEl _dataGrid


list :: El
list = mkDom classList
listItem :: El
listItem = mkDom classListItem
listItemAvatar :: El
listItemAvatar = mkDom classListItemAvatar
listItemIcon :: El
listItemIcon = mkDom classListItemIcon
listItemSecondaryAction :: El
listItemSecondaryAction = mkDom classListItemSecondaryAction
listItemText :: El
listItemText = mkDom classListItemText
listSubheader :: El
listSubheader = mkDom classListSubheader
