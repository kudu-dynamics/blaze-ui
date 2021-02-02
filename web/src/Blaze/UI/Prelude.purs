module Blaze.UI.Prelude
       ( module Blaze.UI.Prelude
       ) where

import Prelude

import Concur.React.Props (ReactProps)
import Concur.React.Props as P
import Control.Alt ((<|>))
import Control.Monad.Except (throwError)
import Data.BigInt (BigInt)
import Data.BigInt as BigInt
import Data.Generic.Rep (class Generic)
import Data.Generic.Rep.Show (genericShow)
import Data.Int as Int
import Data.Lens (Iso')
import Data.Lens.Iso.Newtype (_Newtype)
import Data.List.NonEmpty as NeList
import Data.Maybe (Maybe(..))
import Data.Newtype (class Newtype)
import Foreign (ForeignError(..), unsafeFromForeign, unsafeToForeign)
import Foreign.Generic (defaultOptions, genericDecode, genericEncode)
import Foreign.Generic.Class (class Decode, class Encode)


prop :: forall a b. String -> a -> ReactProps b
prop = P.unsafeMkProp

