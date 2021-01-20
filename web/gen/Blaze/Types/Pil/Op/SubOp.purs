-- File auto generated by purescript-bridge! --
module Blaze.Types.Pil.Op.SubOp where

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

newtype SubOp a
  = SubOp
      { left :: a
      , right :: a
      }


instance showSubOp :: (Show a) => Show (SubOp a) where
  show x = genericShow x
derive instance eqSubOp :: (Eq a) => Eq (SubOp a)
derive instance ordSubOp :: (Ord a) => Ord (SubOp a)
instance encodeSubOp :: (Encode a) => Encode (SubOp a) where
  encode value = genericEncode (defaultOptions { unwrapSingleConstructors = true
                                               , unwrapSingleArguments = true
                                               }) value
instance decodeSubOp :: (Decode a) => Decode (SubOp a) where
  decode value = genericDecode (defaultOptions { unwrapSingleConstructors = true
                                               , unwrapSingleArguments = true
                                               }) value
derive instance genericSubOp :: Generic (SubOp a) _
derive instance newtypeSubOp :: Newtype (SubOp a) _
--------------------------------------------------------------------------------
_SubOp :: forall a. Iso' (SubOp a) { left :: a, right :: a }
_SubOp = _Newtype
--------------------------------------------------------------------------------
