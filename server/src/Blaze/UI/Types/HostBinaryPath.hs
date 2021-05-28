module Blaze.UI.Types.HostBinaryPath where

import Blaze.UI.Prelude
import Data.Text.Encoding.Base64.URL (encodeBase64, decodeBase64)
import Web.Scotty (Parsable(parseParam))

import Database.Selda.SqlType ( Lit(LCustom)
                              , SqlTypeRep(TText)
                              , SqlType(defaultValue)
                              )
import qualified Database.Selda.SqlType as Sql
import qualified Data.Text as Text

-- | This is the path to the binary or bndb on the host running binaryninja
-- This is used as an Id
newtype HostBinaryPath = HostBinaryPath FilePath
  deriving (Eq, Ord, Read, Show, Generic)
  deriving newtype (IsString)
  deriving anyclass (FromJSON, ToJSON, Hashable)

instance Parsable HostBinaryPath where
  parseParam = fmap HostBinaryPath . parseParam

instance SqlType HostBinaryPath where
   mkLit (HostBinaryPath x) = LCustom TText . Sql.mkLit $ (cs x :: Text)
   sqlType _ = TText
   fromSql x = HostBinaryPath . Text.unpack $ Sql.fromSql x
   defaultValue = LCustom TText (Sql.defaultValue :: Lit Text)

fromFilePath :: FilePath -> HostBinaryPath
fromFilePath = HostBinaryPath

encode :: ConvertibleStrings Text a => HostBinaryPath -> a
encode (HostBinaryPath x) = cs . encodeBase64 . cs $ x

decode :: ConvertibleStrings a Text => a -> Either Text HostBinaryPath
decode = fmap (HostBinaryPath . cs) . decodeBase64 . cs

toText :: ConvertibleStrings String a => HostBinaryPath -> a
toText (HostBinaryPath p) = cs p
