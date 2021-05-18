module Blaze.UI.Types.HostBinaryPath where

import Blaze.UI.Prelude
import Data.Text.Encoding.Base64.URL (encodeBase64, decodeBase64)
import Web.Scotty (Parsable(parseParam))

-- | This is the path to the binary or bndb on the host running binaryninja
-- This is used as an Id
newtype HostBinaryPath = HostBinaryPath FilePath
  deriving (Eq, Ord, Read, Show, Generic)
  deriving newtype (IsString)
  deriving anyclass (FromJSON, ToJSON, Hashable)

instance Parsable HostBinaryPath where
  parseParam = fmap HostBinaryPath . parseParam

fromFilePath :: FilePath -> HostBinaryPath
fromFilePath = HostBinaryPath

encode :: ConvertibleStrings Text a => HostBinaryPath -> a
encode (HostBinaryPath x) = cs . encodeBase64 . cs $ x

decode :: ConvertibleStrings a Text => a -> Either Text HostBinaryPath
decode = fmap (HostBinaryPath . cs) . decodeBase64 . cs
