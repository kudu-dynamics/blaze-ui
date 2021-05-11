module Blaze.UI.Types.BinaryHash where

import Blaze.UI.Prelude hiding ((:*:))

import Database.Selda
import Database.Selda.SqlType ( Lit(LCustom)
                              , SqlTypeRep(TBlob)
                              )
import qualified Database.Selda.SqlType as Sql
import qualified Crypto.Hash.MD5 as MD5
import qualified Data.ByteString as BS

newtype BinaryHash = BinaryHash ByteString
  deriving (Eq, Ord, Show, Generic)

instance SqlType BinaryHash where
   mkLit (BinaryHash x) = LCustom TBlob $ Sql.mkLit x
   sqlType _ = TBlob
   fromSql x = BinaryHash $ Sql.fromSql x
   defaultValue = LCustom TBlob (Sql.defaultValue :: Lit ByteString)

getBinaryHash :: FilePath -> IO BinaryHash
getBinaryHash = fmap (BinaryHash . MD5.hash) . BS.readFile
