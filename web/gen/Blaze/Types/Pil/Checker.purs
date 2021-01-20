-- File auto generated by purescript-bridge! --
module Blaze.Types.Pil.Checker where

import Blaze.Types.Pil (ExprOp)
import Data.BinaryAnalysis (Bits)
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
import Prim (Int)

import Prelude

newtype Sym
  = Sym Int


instance showSym :: Show Sym where
  show x = genericShow x
derive instance eqSym :: Eq Sym
derive instance ordSym :: Ord Sym
instance encodeSym :: Encode Sym where
  encode value = genericEncode (defaultOptions { unwrapSingleConstructors = true
                                               , unwrapSingleArguments = true
                                               }) value
instance decodeSym :: Decode Sym where
  decode value = genericDecode (defaultOptions { unwrapSingleConstructors = true
                                               , unwrapSingleArguments = true
                                               }) value
derive instance genericSym :: Generic Sym _
derive instance newtypeSym :: Newtype Sym _
--------------------------------------------------------------------------------
_Sym :: Iso' Sym Int
_Sym = _Newtype
--------------------------------------------------------------------------------
newtype InfoExpression a
  = InfoExpression
      { info :: a
      , op :: ExprOp (InfoExpression a)
      }


instance showInfoExpression :: (Show a) => Show (InfoExpression a) where
  show x = genericShow x
derive instance eqInfoExpression :: (Eq a) => Eq (InfoExpression a)
derive instance ordInfoExpression :: (Ord a) => Ord (InfoExpression a)
instance encodeInfoExpression :: (Encode a) => Encode (InfoExpression a) where
  encode value = genericEncode (defaultOptions { unwrapSingleConstructors = true
                                               , unwrapSingleArguments = true
                                               }) value
instance decodeInfoExpression :: (Decode a) => Decode (InfoExpression a) where
  decode value = genericDecode (defaultOptions { unwrapSingleConstructors = true
                                               , unwrapSingleArguments = true
                                               }) value
derive instance genericInfoExpression :: Generic (InfoExpression a) _
derive instance newtypeInfoExpression :: Newtype (InfoExpression a) _
--------------------------------------------------------------------------------
_InfoExpression :: forall a. Iso' (InfoExpression a) { info :: a
                                                     , op :: ExprOp (InfoExpression a) }
_InfoExpression = _Newtype
--------------------------------------------------------------------------------
newtype SymInfo
  = SymInfo
      { size :: Bits
      , sym :: Sym
      }


instance showSymInfo :: Show SymInfo where
  show x = genericShow x
derive instance eqSymInfo :: Eq SymInfo
derive instance ordSymInfo :: Ord SymInfo
instance encodeSymInfo :: Encode SymInfo where
  encode value = genericEncode (defaultOptions { unwrapSingleConstructors = true
                                               , unwrapSingleArguments = true
                                               }) value
instance decodeSymInfo :: Decode SymInfo where
  decode value = genericDecode (defaultOptions { unwrapSingleConstructors = true
                                               , unwrapSingleArguments = true
                                               }) value
derive instance genericSymInfo :: Generic SymInfo _
derive instance newtypeSymInfo :: Newtype SymInfo _
--------------------------------------------------------------------------------
_SymInfo :: Iso' SymInfo { size :: Bits, sym :: Sym }
_SymInfo = _Newtype
--------------------------------------------------------------------------------
