module Data.Word64 where

import Prelude

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

newtype Word64 = Word64 BigInt

instance showWord64 :: Show Word64 where
  show (Word64 x) = BigInt.toString x
derive instance eqWord64 :: Eq Word64
derive instance ordWord64 :: Ord Word64
instance encodeWord64 :: Encode Word64 where
  encode (Word64 n) = unsafeToForeign $ BigInt.toNumber n
instance decodeWord64 :: Decode Word64 where
  decode x = case Word64 <$> (BigInt.fromNumber $ unsafeFromForeign x) of
    Nothing -> throwError $
               NeList.singleton (ForeignError "Cannot create bigint")
    Just y -> pure y

derive instance genericWord64 :: Generic Word64 _
derive instance newtypeWord64 :: Newtype Word64 _
--------------------------------------------------------------------------------
_Word64 :: Iso' Word64 BigInt
_Word64 = _Newtype
