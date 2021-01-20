-- File auto generated by purescript-bridge! --
module Blaze.Types.Pil.Op.FloatToIntOp where

import Data.Generic.Rep (class Generic)
import Data.Generic.Rep.Show (genericShow)
import Data.Lens (Iso', Lens', Prism', lens, prism')
import Data.Lens.Iso.Newtype (_Newtype)
import Data.Lens.Record (prop)
import Data.Maybe (Maybe(..))
import Data.Newtype (class Newtype)
import Data.Symbol (SProxy(SProxy))
import Foreign.Class (class Decode, class Encode)
import Foreign.Generic (aesonSumEncoding, defaultOptions, genericDecode, genericEncode)
import Foreign.Generic.EnumEncoding (defaultGenericEnumOptions, genericDecodeEnum, genericEncodeEnum)

import Prelude

newtype FloatToIntOp a
  = FloatToIntOp
      { src :: a
      }


instance showFloatToIntOp :: (Show a) => Show (FloatToIntOp a) where
  show x = genericShow x
derive instance eqFloatToIntOp :: (Eq a) => Eq (FloatToIntOp a)
derive instance ordFloatToIntOp :: (Ord a) => Ord (FloatToIntOp a)
instance encodeFloatToIntOp :: (Encode a) => Encode (FloatToIntOp a) where
  encode value = genericEncode (defaultOptions { unwrapSingleConstructors = true
                                               , unwrapSingleArguments = true
                                               }) value
instance decodeFloatToIntOp :: (Decode a) => Decode (FloatToIntOp a) where
  decode value = genericDecode (defaultOptions { unwrapSingleConstructors = true
                                               , unwrapSingleArguments = true
                                               }) value
derive instance genericFloatToIntOp :: Generic (FloatToIntOp a) _
derive instance newtypeFloatToIntOp :: Newtype (FloatToIntOp a) _
--------------------------------------------------------------------------------
_FloatToIntOp :: forall a. Iso' (FloatToIntOp a) { src :: a }
_FloatToIntOp = _Newtype
--------------------------------------------------------------------------------
