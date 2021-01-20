-- File auto generated by purescript-bridge! --
module Blaze.Types.Pil.Op.MulOp where

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

newtype MulOp a
  = MulOp
      { left :: a
      , right :: a
      }


instance showMulOp :: (Show a) => Show (MulOp a) where
  show x = genericShow x
derive instance eqMulOp :: (Eq a) => Eq (MulOp a)
derive instance ordMulOp :: (Ord a) => Ord (MulOp a)
instance encodeMulOp :: (Encode a) => Encode (MulOp a) where
  encode value = genericEncode (defaultOptions { unwrapSingleConstructors = true
                                               , unwrapSingleArguments = true
                                               }) value
instance decodeMulOp :: (Decode a) => Decode (MulOp a) where
  decode value = genericDecode (defaultOptions { unwrapSingleConstructors = true
                                               , unwrapSingleArguments = true
                                               }) value
derive instance genericMulOp :: Generic (MulOp a) _
derive instance newtypeMulOp :: Newtype (MulOp a) _
--------------------------------------------------------------------------------
_MulOp :: forall a. Iso' (MulOp a) { left :: a, right :: a }
_MulOp = _Newtype
--------------------------------------------------------------------------------
