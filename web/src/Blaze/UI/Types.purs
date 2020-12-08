module Blaze.UI.Types where

import Prelude

import Control.Alternative as Alt
import Blaze.Types.CallGraph as CG
import Data.Generic.Rep (class Generic)
import Data.Generic.Rep.Show (genericShow)



data Nav = NavBinaryView
         | NavFunctionView CG.Function

instance showNav :: Show Nav where
  show x = genericShow x
derive instance eqNav :: Eq Nav
derive instance ordNav :: Ord Nav
derive instance genericNav :: Generic Nav _

