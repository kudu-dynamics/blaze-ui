module Data.Int64 where

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

newtype Int64 = Int64 BigInt

instance showInt64 :: Show Int64 where
  show (Int64 x) = BigInt.toString x
derive instance eqInt64 :: Eq Int64
derive instance ordInt64 :: Ord Int64
instance encodeInt64 :: Encode Int64 where
  encode (Int64 n) = unsafeToForeign $ BigInt.toNumber n
instance decodeInt64 :: Decode Int64 where
  decode x = case Int64 <$> (BigInt.fromNumber $ unsafeFromForeign x) of
    Nothing -> throwError $
               NeList.singleton (ForeignError "Cannot create bigint")
    Just y -> pure y

derive instance genericInt64 :: Generic Int64 _
derive instance newtypeInt64 :: Newtype Int64 _
--------------------------------------------------------------------------------
_Int64 :: Iso' Int64 BigInt
_Int64 = _Newtype
