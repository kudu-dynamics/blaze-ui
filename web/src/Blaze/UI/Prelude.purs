module Blaze.UI.Prelude
       ( module Blaze.UI.Prelude
       ) where

import Prelude
import Concur.React.Props (ReactProps)
import Concur.React.Props as P
import Data.Int as Int

showHex :: Int -> String
showHex = ("0x" <> _) <<< Int.toStringAs Int.hexadecimal

prop :: forall a b. String -> a -> ReactProps b
prop = P.unsafeMkProp

       
