module Blaze.UI.Types.BndbHash where

import Blaze.UI.Prelude hiding ((:*:))

import Database.Selda
import Database.Selda.SqlType ( Lit(LCustom)
                              , SqlTypeRep(TText)
                              )
import qualified Database.Selda.SqlType as Sql
import qualified Crypto.Hash.MD5 as MD5
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as B16

-- | Hash digest specifically for BNDBs.
-- This does not use a newtype around BinaryHash because it complicates
-- the SqlType instance, which makes heavy use of phantom types.
newtype BndbHash = BndbHash Text
  deriving (Eq, Ord, Show, Generic)
  deriving newtype (Hashable, ToJSON, FromJSON)

instance SqlType BndbHash where
   mkLit (BndbHash x) = LCustom TText $ Sql.mkLit x
   sqlType _ = TText
   fromSql x = BndbHash $ Sql.fromSql x
   defaultValue = LCustom TText (Sql.defaultValue :: Lit Text)

-- TODO: crashes if file does not exist
fromFile :: MonadIO m => FilePath -> m BndbHash
fromFile = liftIO . fmap fromByteString . BS.readFile

fromByteString :: ByteString -> BndbHash
fromByteString = BndbHash . cs . B16.encode . MD5.hash

toText :: ConvertibleStrings Text a => BndbHash -> a
toText (BndbHash h) = cs h
