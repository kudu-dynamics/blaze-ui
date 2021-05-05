-- File auto generated by purescript-bridge! --
module Blaze.Types.Function where

import Data.BinaryAnalysis (Address, Symbol)
import Data.Generic.Rep (class Generic)
import Data.Generic.Rep.Show (genericShow)
import Data.Lens (Iso', Lens', Prism', lens, prism')
import Data.Lens.Iso.Newtype (_Newtype)
import Data.Lens.Record (prop)
import Data.Maybe (Maybe, Maybe(..))
import Data.Newtype (class Newtype)
import Data.Symbol (SProxy(SProxy))
import Foreign.Class (class Decode, class Encode)
import Foreign.Generic (aesonSumEncoding, defaultOptions, genericDecode, genericEncode)
import Foreign.Generic.EnumEncoding (defaultGenericEnumOptions, genericDecodeEnum, genericEncodeEnum)
import Prim (Array, String)

import Prelude

newtype Function
  = Function
      { symbol :: Maybe Symbol
      , name :: String
      , address :: Address
      , params :: Array FuncParamInfo
      }


instance showFunction :: Show Function where
  show x = genericShow x
derive instance eqFunction :: Eq Function
derive instance ordFunction :: Ord Function
instance encodeFunction :: Encode Function where
  encode value = genericEncode (defaultOptions { unwrapSingleConstructors = true
                                               , unwrapSingleArguments = true
                                               }) value
instance decodeFunction :: Decode Function where
  decode value = genericDecode (defaultOptions { unwrapSingleConstructors = true
                                               , unwrapSingleArguments = true
                                               }) value
derive instance genericFunction :: Generic Function _
derive instance newtypeFunction :: Newtype Function _
--------------------------------------------------------------------------------
_Function :: Iso' Function { symbol :: Maybe Symbol
                           , name :: String
                           , address :: Address
                           , params :: Array FuncParamInfo }
_Function = _Newtype
--------------------------------------------------------------------------------