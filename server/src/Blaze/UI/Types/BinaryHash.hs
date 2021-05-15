module Blaze.UI.Types.BinaryHash where

import Blaze.UI.Prelude hiding ((:*:))

import Database.Selda
import Database.Selda.SqlType ( Lit(LCustom)
                              , SqlTypeRep(TBlob)
                              )
import qualified Database.Selda.SqlType as Sql
import qualified Crypto.Hash.MD5 as MD5
import qualified Data.ByteString as BS
import qualified Data.Aeson as Aeson

newtype BinaryHash = BinaryHash ByteString
  deriving (Eq, Ord, Show, Generic)
  deriving newtype (Hashable)

instance FromJSON BinaryHash where
  parseJSON x = BinaryHash . f <$> Aeson.parseJSON x
    where
      f :: Text -> ByteString
      f = cs

instance ToJSON BinaryHash where
  toJSON (BinaryHash x) = Aeson.toJSON (cs x :: Text)


instance SqlType BinaryHash where
   mkLit (BinaryHash x) = LCustom TBlob $ Sql.mkLit x
   sqlType _ = TBlob
   fromSql x = BinaryHash $ Sql.fromSql x
   defaultValue = LCustom TBlob (Sql.defaultValue :: Lit ByteString)

-- TODO: crashes if file does not exist
fromFile :: MonadIO m => FilePath -> m BinaryHash
fromFile = liftIO . fmap fromByteString . BS.readFile

fromByteString :: ByteString -> BinaryHash
fromByteString = BinaryHash . MD5.hash

toString :: ConvertibleStrings ByteString a => BinaryHash -> a
toString (BinaryHash h) = cs h
