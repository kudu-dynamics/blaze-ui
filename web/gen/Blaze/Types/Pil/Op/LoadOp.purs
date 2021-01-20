-- File auto generated by purescript-bridge! --
module Blaze.Types.Pil.Op.LoadOp where

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

newtype LoadOp a
  = LoadOp
      { src :: a
      }


instance showLoadOp :: (Show a) => Show (LoadOp a) where
  show x = genericShow x
derive instance eqLoadOp :: (Eq a) => Eq (LoadOp a)
derive instance ordLoadOp :: (Ord a) => Ord (LoadOp a)
instance encodeLoadOp :: (Encode a) => Encode (LoadOp a) where
  encode value = genericEncode (defaultOptions { unwrapSingleConstructors = true
                                               , unwrapSingleArguments = true
                                               }) value
instance decodeLoadOp :: (Decode a) => Decode (LoadOp a) where
  decode value = genericDecode (defaultOptions { unwrapSingleConstructors = true
                                               , unwrapSingleArguments = true
                                               }) value
derive instance genericLoadOp :: Generic (LoadOp a) _
derive instance newtypeLoadOp :: Newtype (LoadOp a) _
--------------------------------------------------------------------------------
_LoadOp :: forall a. Iso' (LoadOp a) { src :: a }
_LoadOp = _Newtype
--------------------------------------------------------------------------------
