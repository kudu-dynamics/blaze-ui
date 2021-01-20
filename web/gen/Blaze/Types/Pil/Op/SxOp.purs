-- File auto generated by purescript-bridge! --
module Blaze.Types.Pil.Op.SxOp where

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

newtype SxOp a
  = SxOp
      { src :: a
      }


instance showSxOp :: (Show a) => Show (SxOp a) where
  show x = genericShow x
derive instance eqSxOp :: (Eq a) => Eq (SxOp a)
derive instance ordSxOp :: (Ord a) => Ord (SxOp a)
instance encodeSxOp :: (Encode a) => Encode (SxOp a) where
  encode value = genericEncode (defaultOptions { unwrapSingleConstructors = true
                                               , unwrapSingleArguments = true
                                               }) value
instance decodeSxOp :: (Decode a) => Decode (SxOp a) where
  decode value = genericDecode (defaultOptions { unwrapSingleConstructors = true
                                               , unwrapSingleArguments = true
                                               }) value
derive instance genericSxOp :: Generic (SxOp a) _
derive instance newtypeSxOp :: Newtype (SxOp a) _
--------------------------------------------------------------------------------
_SxOp :: forall a. Iso' (SxOp a) { src :: a }
_SxOp = _Newtype
--------------------------------------------------------------------------------
