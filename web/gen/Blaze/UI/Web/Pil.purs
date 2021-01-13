-- File auto generated by purescript-bridge! --
module Blaze.UI.Web.Pil where

import Blaze.Types.Pil (Statement)
import Blaze.Types.Pil.Common (PilVar)
import Data.BinaryAnalysis (BitOffset, Bits)
import Data.Generic.Rep (class Generic)
import Data.Generic.Rep.Show (genericShow)
import Data.Lens (Iso', Lens', Prism', lens, prism')
import Data.Lens.Iso.Newtype (_Newtype)
import Data.Lens.Record (prop)
import Data.Maybe (Maybe, Maybe(..))
import Data.Newtype (class Newtype)
import Data.Symbol (SProxy(SProxy))
import Data.Tuple (Tuple)
import Foreign.Class (class Decode, class Encode)
import Foreign.Generic (aesonSumEncoding, defaultOptions, genericDecode, genericEncode)
import Foreign.Generic.EnumEncoding (defaultGenericEnumOptions, genericDecodeEnum, genericEncodeEnum)
import Prim (Array, Boolean, Int, String)

import Prelude

data PilType a
  = TBool
  | TChar
  | TInt (TIntOp a)
  | TFloat (TFloatOp a)
  | TBitVector (TBitVectorOp a)
  | TPointer (TPointerOp a)
  | TArray (TArrayOp a)
  | TRecord (Array (Tuple BitOffset a))
  | TBottom Sym
  | TFunction (TFunctionOp a)
  | TVBitWidth Bits
  | TVLength Int
  | TVSign Boolean


instance showPilType :: (Show a) => Show (PilType a) where
  show x = genericShow x
derive instance eqPilType :: (Eq a) => Eq (PilType a)
derive instance ordPilType :: (Ord a) => Ord (PilType a)
instance encodePilType :: (Encode a) => Encode (PilType a) where
  encode value = genericEncode (defaultOptions { unwrapSingleConstructors = true
                                               , unwrapSingleArguments = true
                                               }) value
instance decodePilType :: (Decode a) => Decode (PilType a) where
  decode value = genericDecode (defaultOptions { unwrapSingleConstructors = true
                                               , unwrapSingleArguments = true
                                               }) value
derive instance genericPilType :: Generic (PilType a) _
--------------------------------------------------------------------------------
_TBool :: forall a. Prism' (PilType a) Unit
_TBool = prism' (\_ -> TBool) f
  where
    f TBool = Just unit
    f _ = Nothing

_TChar :: forall a. Prism' (PilType a) Unit
_TChar = prism' (\_ -> TChar) f
  where
    f TChar = Just unit
    f _ = Nothing

_TInt :: forall a. Prism' (PilType a) (TIntOp a)
_TInt = prism' TInt f
  where
    f (TInt a) = Just $ a
    f _ = Nothing

_TFloat :: forall a. Prism' (PilType a) (TFloatOp a)
_TFloat = prism' TFloat f
  where
    f (TFloat a) = Just $ a
    f _ = Nothing

_TBitVector :: forall a. Prism' (PilType a) (TBitVectorOp a)
_TBitVector = prism' TBitVector f
  where
    f (TBitVector a) = Just $ a
    f _ = Nothing

_TPointer :: forall a. Prism' (PilType a) (TPointerOp a)
_TPointer = prism' TPointer f
  where
    f (TPointer a) = Just $ a
    f _ = Nothing

_TArray :: forall a. Prism' (PilType a) (TArrayOp a)
_TArray = prism' TArray f
  where
    f (TArray a) = Just $ a
    f _ = Nothing

_TRecord :: forall a. Prism' (PilType a) (Array (Tuple BitOffset a))
_TRecord = prism' TRecord f
  where
    f (TRecord a) = Just $ a
    f _ = Nothing

_TBottom :: forall a. Prism' (PilType a) Sym
_TBottom = prism' TBottom f
  where
    f (TBottom a) = Just $ a
    f _ = Nothing

_TFunction :: forall a. Prism' (PilType a) (TFunctionOp a)
_TFunction = prism' TFunction f
  where
    f (TFunction a) = Just $ a
    f _ = Nothing

_TVBitWidth :: forall a. Prism' (PilType a) Bits
_TVBitWidth = prism' TVBitWidth f
  where
    f (TVBitWidth a) = Just $ a
    f _ = Nothing

_TVLength :: forall a. Prism' (PilType a) Int
_TVLength = prism' TVLength f
  where
    f (TVLength a) = Just $ a
    f _ = Nothing

_TVSign :: forall a. Prism' (PilType a) Boolean
_TVSign = prism' TVSign f
  where
    f (TVSign a) = Just $ a
    f _ = Nothing
--------------------------------------------------------------------------------
newtype TIntOp a
  = TIntOp
      { bitWidth :: a
      , signed :: a
      }


instance showTIntOp :: (Show a) => Show (TIntOp a) where
  show x = genericShow x
derive instance eqTIntOp :: (Eq a) => Eq (TIntOp a)
derive instance ordTIntOp :: (Ord a) => Ord (TIntOp a)
instance encodeTIntOp :: (Encode a) => Encode (TIntOp a) where
  encode value = genericEncode (defaultOptions { unwrapSingleConstructors = true
                                               , unwrapSingleArguments = true
                                               }) value
instance decodeTIntOp :: (Decode a) => Decode (TIntOp a) where
  decode value = genericDecode (defaultOptions { unwrapSingleConstructors = true
                                               , unwrapSingleArguments = true
                                               }) value
derive instance genericTIntOp :: Generic (TIntOp a) _
derive instance newtypeTIntOp :: Newtype (TIntOp a) _
--------------------------------------------------------------------------------
_TIntOp :: forall a. Iso' (TIntOp a) { bitWidth :: a, signed :: a }
_TIntOp = _Newtype
--------------------------------------------------------------------------------
newtype TFloatOp a
  = TFloatOp
      { bitWidth :: a
      }


instance showTFloatOp :: (Show a) => Show (TFloatOp a) where
  show x = genericShow x
derive instance eqTFloatOp :: (Eq a) => Eq (TFloatOp a)
derive instance ordTFloatOp :: (Ord a) => Ord (TFloatOp a)
instance encodeTFloatOp :: (Encode a) => Encode (TFloatOp a) where
  encode value = genericEncode (defaultOptions { unwrapSingleConstructors = true
                                               , unwrapSingleArguments = true
                                               }) value
instance decodeTFloatOp :: (Decode a) => Decode (TFloatOp a) where
  decode value = genericDecode (defaultOptions { unwrapSingleConstructors = true
                                               , unwrapSingleArguments = true
                                               }) value
derive instance genericTFloatOp :: Generic (TFloatOp a) _
derive instance newtypeTFloatOp :: Newtype (TFloatOp a) _
--------------------------------------------------------------------------------
_TFloatOp :: forall a. Iso' (TFloatOp a) { bitWidth :: a }
_TFloatOp = _Newtype
--------------------------------------------------------------------------------
newtype TBitVectorOp a
  = TBitVectorOp
      { bitWidth :: a
      }


instance showTBitVectorOp :: (Show a) => Show (TBitVectorOp a) where
  show x = genericShow x
derive instance eqTBitVectorOp :: (Eq a) => Eq (TBitVectorOp a)
derive instance ordTBitVectorOp :: (Ord a) => Ord (TBitVectorOp a)
instance encodeTBitVectorOp :: (Encode a) => Encode (TBitVectorOp a) where
  encode value = genericEncode (defaultOptions { unwrapSingleConstructors = true
                                               , unwrapSingleArguments = true
                                               }) value
instance decodeTBitVectorOp :: (Decode a) => Decode (TBitVectorOp a) where
  decode value = genericDecode (defaultOptions { unwrapSingleConstructors = true
                                               , unwrapSingleArguments = true
                                               }) value
derive instance genericTBitVectorOp :: Generic (TBitVectorOp a) _
derive instance newtypeTBitVectorOp :: Newtype (TBitVectorOp a) _
--------------------------------------------------------------------------------
_TBitVectorOp :: forall a. Iso' (TBitVectorOp a) { bitWidth :: a }
_TBitVectorOp = _Newtype
--------------------------------------------------------------------------------
newtype TPointerOp a
  = TPointerOp
      { bitWidth :: a
      , pointeeType :: a
      }


instance showTPointerOp :: (Show a) => Show (TPointerOp a) where
  show x = genericShow x
derive instance eqTPointerOp :: (Eq a) => Eq (TPointerOp a)
derive instance ordTPointerOp :: (Ord a) => Ord (TPointerOp a)
instance encodeTPointerOp :: (Encode a) => Encode (TPointerOp a) where
  encode value = genericEncode (defaultOptions { unwrapSingleConstructors = true
                                               , unwrapSingleArguments = true
                                               }) value
instance decodeTPointerOp :: (Decode a) => Decode (TPointerOp a) where
  decode value = genericDecode (defaultOptions { unwrapSingleConstructors = true
                                               , unwrapSingleArguments = true
                                               }) value
derive instance genericTPointerOp :: Generic (TPointerOp a) _
derive instance newtypeTPointerOp :: Newtype (TPointerOp a) _
--------------------------------------------------------------------------------
_TPointerOp :: forall a. Iso' (TPointerOp a) { bitWidth :: a, pointeeType :: a }
_TPointerOp = _Newtype
--------------------------------------------------------------------------------
newtype TArrayOp a
  = TArrayOp
      { len :: a
      , elemType :: a
      }


instance showTArrayOp :: (Show a) => Show (TArrayOp a) where
  show x = genericShow x
derive instance eqTArrayOp :: (Eq a) => Eq (TArrayOp a)
derive instance ordTArrayOp :: (Ord a) => Ord (TArrayOp a)
instance encodeTArrayOp :: (Encode a) => Encode (TArrayOp a) where
  encode value = genericEncode (defaultOptions { unwrapSingleConstructors = true
                                               , unwrapSingleArguments = true
                                               }) value
instance decodeTArrayOp :: (Decode a) => Decode (TArrayOp a) where
  decode value = genericDecode (defaultOptions { unwrapSingleConstructors = true
                                               , unwrapSingleArguments = true
                                               }) value
derive instance genericTArrayOp :: Generic (TArrayOp a) _
derive instance newtypeTArrayOp :: Newtype (TArrayOp a) _
--------------------------------------------------------------------------------
_TArrayOp :: forall a. Iso' (TArrayOp a) { len :: a, elemType :: a }
_TArrayOp = _Newtype
--------------------------------------------------------------------------------
newtype TFunctionOp a
  = TFunctionOp
      { ret :: a
      , params :: Array a
      }


instance showTFunctionOp :: (Show a) => Show (TFunctionOp a) where
  show x = genericShow x
derive instance eqTFunctionOp :: (Eq a) => Eq (TFunctionOp a)
derive instance ordTFunctionOp :: (Ord a) => Ord (TFunctionOp a)
instance encodeTFunctionOp :: (Encode a) => Encode (TFunctionOp a) where
  encode value = genericEncode (defaultOptions { unwrapSingleConstructors = true
                                               , unwrapSingleArguments = true
                                               }) value
instance decodeTFunctionOp :: (Decode a) => Decode (TFunctionOp a) where
  decode value = genericDecode (defaultOptions { unwrapSingleConstructors = true
                                               , unwrapSingleArguments = true
                                               }) value
derive instance genericTFunctionOp :: Generic (TFunctionOp a) _
derive instance newtypeTFunctionOp :: Newtype (TFunctionOp a) _
--------------------------------------------------------------------------------
_TFunctionOp :: forall a. Iso' (TFunctionOp a) { ret :: a, params :: Array a }
_TFunctionOp = _Newtype
--------------------------------------------------------------------------------
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
newtype TypeError
  = TypeError
      { stmtOrigin :: Int
      , sym :: Sym
      , error :: String
      }


instance showTypeError :: Show TypeError where
  show x = genericShow x
derive instance eqTypeError :: Eq TypeError
derive instance ordTypeError :: Ord TypeError
instance encodeTypeError :: Encode TypeError where
  encode value = genericEncode (defaultOptions { unwrapSingleConstructors = true
                                               , unwrapSingleArguments = true
                                               }) value
instance decodeTypeError :: Decode TypeError where
  decode value = genericDecode (defaultOptions { unwrapSingleConstructors = true
                                               , unwrapSingleArguments = true
                                               }) value
derive instance genericTypeError :: Generic TypeError _
derive instance newtypeTypeError :: Newtype TypeError _
--------------------------------------------------------------------------------
_TypeError :: Iso' TypeError { stmtOrigin :: Int, sym :: Sym, error :: String }
_TypeError = _Newtype
--------------------------------------------------------------------------------
newtype TypeReport
  = TypeReport
      { typedStmts :: Array (Tuple Int (Statement TypedExpr))
      , errors :: Array TypeError
      , varSymTypeMap :: Array (Tuple PilVar DeepSymType)
      , varSymMap :: Array (Tuple PilVar Sym)
      }


instance showTypeReport :: Show TypeReport where
  show x = genericShow x
derive instance eqTypeReport :: Eq TypeReport
derive instance ordTypeReport :: Ord TypeReport
instance encodeTypeReport :: Encode TypeReport where
  encode value = genericEncode (defaultOptions { unwrapSingleConstructors = true
                                               , unwrapSingleArguments = true
                                               }) value
instance decodeTypeReport :: Decode TypeReport where
  decode value = genericDecode (defaultOptions { unwrapSingleConstructors = true
                                               , unwrapSingleArguments = true
                                               }) value
derive instance genericTypeReport :: Generic TypeReport _
derive instance newtypeTypeReport :: Newtype TypeReport _
--------------------------------------------------------------------------------
_TypeReport :: Iso' TypeReport { typedStmts :: Array (Tuple Int (Statement TypedExpr))
                               , errors :: Array TypeError
                               , varSymTypeMap :: Array (Tuple PilVar DeepSymType)
                               , varSymMap :: Array (Tuple PilVar Sym) }
_TypeReport = _Newtype
--------------------------------------------------------------------------------
newtype TypedExpr
  = TypedExpr
      { sym :: Sym
      , op :: String
      , pilType :: Maybe DeepSymType
      , args :: Array TypedExpr
      }


instance showTypedExpr :: Show TypedExpr where
  show x = genericShow x
derive instance eqTypedExpr :: Eq TypedExpr
derive instance ordTypedExpr :: Ord TypedExpr
instance encodeTypedExpr :: Encode TypedExpr where
  encode value = genericEncode (defaultOptions { unwrapSingleConstructors = true
                                               , unwrapSingleArguments = true
                                               }) value
instance decodeTypedExpr :: Decode TypedExpr where
  decode value = genericDecode (defaultOptions { unwrapSingleConstructors = true
                                               , unwrapSingleArguments = true
                                               }) value
derive instance genericTypedExpr :: Generic TypedExpr _
derive instance newtypeTypedExpr :: Newtype TypedExpr _
--------------------------------------------------------------------------------
_TypedExpr :: Iso' TypedExpr { sym :: Sym
                             , op :: String
                             , pilType :: Maybe DeepSymType
                             , args :: Array TypedExpr }
_TypedExpr = _Newtype
--------------------------------------------------------------------------------
data DeepSymType
  = DSVar Sym
  | DSRecursive Sym (PilType DeepSymType)
  | DSType (PilType DeepSymType)


instance showDeepSymType :: Show DeepSymType where
  show x = genericShow x
derive instance eqDeepSymType :: Eq DeepSymType
derive instance ordDeepSymType :: Ord DeepSymType
instance encodeDeepSymType :: Encode DeepSymType where
  encode value = genericEncode (defaultOptions { unwrapSingleConstructors = true
                                               , unwrapSingleArguments = true
                                               }) value
instance decodeDeepSymType :: Decode DeepSymType where
  decode value = genericDecode (defaultOptions { unwrapSingleConstructors = true
                                               , unwrapSingleArguments = true
                                               }) value
derive instance genericDeepSymType :: Generic DeepSymType _
--------------------------------------------------------------------------------
_DSVar :: Prism' DeepSymType Sym
_DSVar = prism' DSVar f
  where
    f (DSVar a) = Just $ a
    f _ = Nothing

_DSRecursive :: Prism' DeepSymType { a :: Sym, b :: PilType DeepSymType }
_DSRecursive = prism' (\{ a, b } -> DSRecursive a b) f
  where
    f (DSRecursive a b) = Just $ { a: a, b: b }
    f _ = Nothing

_DSType :: Prism' DeepSymType (PilType DeepSymType)
_DSType = prism' DSType f
  where
    f (DSType a) = Just $ a
    f _ = Nothing
--------------------------------------------------------------------------------
