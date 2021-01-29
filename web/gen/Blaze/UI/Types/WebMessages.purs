-- File auto generated by purescript-bridge! --
module Blaze.UI.Types.WebMessages where

import Blaze.Types.CallGraph (Function)
import Blaze.Types.Pil (Statement)
import Blaze.Types.Pil.Checker (InfoExpression, SymInfo)
import Blaze.UI.Web.Pil (DeepSymType, TypeReport)
import Data.Generic.Rep (class Generic)
import Data.Generic.Rep.Show (genericShow)
import Data.Lens (Iso', Lens', Prism', lens, prism')
import Data.Lens.Iso.Newtype (_Newtype)
import Data.Lens.Record (prop)
import Data.Maybe (Maybe(..))
import Data.Newtype (class Newtype)
import Data.Symbol (SProxy(SProxy))
import Data.Tuple (Tuple)
import Foreign.Class (class Decode, class Encode)
import Foreign.Generic (aesonSumEncoding, defaultOptions, genericDecode, genericEncode)
import Foreign.Generic.EnumEncoding (defaultGenericEnumOptions, genericDecodeEnum, genericEncodeEnum)
import Prim (Array, Int, String)

import Prelude

data ServerToWeb
  = SWTextMessage String
  | SWLogInfo String
  | SWLogWarn String
  | SWLogError String
  | SWPilType DeepSymType
  | SWProblemType (Array (Tuple Int (Statement (InfoExpression SymInfo))))
  | SWNoop
  | SWFunctionsList (Array Function)
  | SWFunctionTypeReport TypeReport


instance showServerToWeb :: Show ServerToWeb where
  show x = genericShow x
derive instance eqServerToWeb :: Eq ServerToWeb
derive instance ordServerToWeb :: Ord ServerToWeb
instance encodeServerToWeb :: Encode ServerToWeb where
  encode value = genericEncode (defaultOptions { unwrapSingleConstructors = true
                                               , unwrapSingleArguments = true
                                               }) value
instance decodeServerToWeb :: Decode ServerToWeb where
  decode value = genericDecode (defaultOptions { unwrapSingleConstructors = true
                                               , unwrapSingleArguments = true
                                               }) value
derive instance genericServerToWeb :: Generic ServerToWeb _
--------------------------------------------------------------------------------
_SWTextMessage :: Prism' ServerToWeb String
_SWTextMessage = prism' SWTextMessage f
  where
    f (SWTextMessage a) = Just $ a
    f _ = Nothing

_SWLogInfo :: Prism' ServerToWeb String
_SWLogInfo = prism' SWLogInfo f
  where
    f (SWLogInfo a) = Just $ a
    f _ = Nothing

_SWLogWarn :: Prism' ServerToWeb String
_SWLogWarn = prism' SWLogWarn f
  where
    f (SWLogWarn a) = Just $ a
    f _ = Nothing

_SWLogError :: Prism' ServerToWeb String
_SWLogError = prism' SWLogError f
  where
    f (SWLogError a) = Just $ a
    f _ = Nothing

_SWPilType :: Prism' ServerToWeb DeepSymType
_SWPilType = prism' SWPilType f
  where
    f (SWPilType a) = Just $ a
    f _ = Nothing

_SWProblemType :: Prism' ServerToWeb (Array (Tuple Int (Statement (InfoExpression SymInfo))))
_SWProblemType = prism' SWProblemType f
  where
    f (SWProblemType a) = Just $ a
    f _ = Nothing

_SWNoop :: Prism' ServerToWeb Unit
_SWNoop = prism' (\_ -> SWNoop) f
  where
    f SWNoop = Just unit
    f _ = Nothing

_SWFunctionsList :: Prism' ServerToWeb (Array Function)
_SWFunctionsList = prism' SWFunctionsList f
  where
    f (SWFunctionsList a) = Just $ a
    f _ = Nothing

_SWFunctionTypeReport :: Prism' ServerToWeb TypeReport
_SWFunctionTypeReport = prism' SWFunctionTypeReport f
  where
    f (SWFunctionTypeReport a) = Just $ a
    f _ = Nothing
--------------------------------------------------------------------------------
data WebToServer
  = WSTextMessage String
  | WSGetFunctionsList
  | WSGetTypeReport Function
  | WSNoop


instance showWebToServer :: Show WebToServer where
  show x = genericShow x
derive instance eqWebToServer :: Eq WebToServer
derive instance ordWebToServer :: Ord WebToServer
instance encodeWebToServer :: Encode WebToServer where
  encode value = genericEncode (defaultOptions { unwrapSingleConstructors = true
                                               , unwrapSingleArguments = true
                                               }) value
instance decodeWebToServer :: Decode WebToServer where
  decode value = genericDecode (defaultOptions { unwrapSingleConstructors = true
                                               , unwrapSingleArguments = true
                                               }) value
derive instance genericWebToServer :: Generic WebToServer _
--------------------------------------------------------------------------------
_WSTextMessage :: Prism' WebToServer String
_WSTextMessage = prism' WSTextMessage f
  where
    f (WSTextMessage a) = Just $ a
    f _ = Nothing

_WSGetFunctionsList :: Prism' WebToServer Unit
_WSGetFunctionsList = prism' (\_ -> WSGetFunctionsList) f
  where
    f WSGetFunctionsList = Just unit
    f _ = Nothing

_WSGetTypeReport :: Prism' WebToServer Function
_WSGetTypeReport = prism' WSGetTypeReport f
  where
    f (WSGetTypeReport a) = Just $ a
    f _ = Nothing

_WSNoop :: Prism' WebToServer Unit
_WSNoop = prism' (\_ -> WSNoop) f
  where
    f WSNoop = Just unit
    f _ = Nothing
--------------------------------------------------------------------------------
