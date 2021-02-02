module Blaze.UI.Classes.ShowHex where

import Data.Monoid
import Prelude

import Blaze.Types.Pil.Common (StackOffset(..))
import Data.BigInt as BigInt
import Data.BinaryAnalysis (Address(..), Bits(..), ByteOffset(..), Bytes(..))
import Data.Int64 (Int64(..))
import Data.Word64 (Word64(..))

class ShowHex a where
  showHex :: a -> String


instance int64ShowHex :: ShowHex Int64 where
  showHex (Int64 x) = "0x" <> BigInt.toBase 16 x

instance word64ShowHex :: ShowHex Word64 where
  showHex (Word64 x) = "0x" <> BigInt.toBase 16 x

instance bytesShowHex :: ShowHex Bytes where
  showHex (Bytes x) = showHex x

instance bitsShowHex :: ShowHex Bits where
  showHex (Bits x) = showHex x

instance addressShowHex :: ShowHex Address where
  showHex (Address x) = showHex x

instance byteOffsetShowHex :: ShowHex ByteOffset where
  showHex (ByteOffset x) = showHex x

instance stackOffsetShowHex :: ShowHex StackOffset where
  showHex (StackOffset x) = showHex x.offset
         
