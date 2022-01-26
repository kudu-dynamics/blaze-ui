module Blaze.UI.Types.BinaryHash where

import Blaze.UI.Prelude hiding ((:*:))

import Database.Selda
import Database.Selda.SqlType ( Lit(LCustom)
                              , SqlTypeRep(TText)
                              )
import qualified Database.Selda.SqlType as Sql
import qualified Crypto.Hash.MD5 as MD5
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as B16
import Web.Scotty (Parsable(parseParam))


newtype BinaryHash = BinaryHash Text
  deriving (Eq, Ord, Show, Generic)
  deriving newtype (Hashable, ToJSON, FromJSON)

instance SqlType BinaryHash where
   mkLit (BinaryHash x) = LCustom TText $ Sql.mkLit x
   sqlType _ = TText
   fromSql x = BinaryHash $ Sql.fromSql x
   defaultValue = LCustom TText (Sql.defaultValue :: Lit Text)

instance Parsable BinaryHash where
  parseParam = Right . BinaryHash . cs

-- TODO: crashes if file does not exist
fromFile :: MonadIO m => FilePath -> m BinaryHash
fromFile = liftIO . fmap fromByteString . BS.readFile

fromByteString :: ByteString -> BinaryHash
fromByteString = BinaryHash . cs . B16.encode . MD5.hash

toText :: ConvertibleStrings Text a => BinaryHash -> a
toText (BinaryHash h) = cs h
