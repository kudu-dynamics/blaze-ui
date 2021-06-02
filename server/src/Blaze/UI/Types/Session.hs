module Blaze.UI.Types.Session where

import Blaze.UI.Prelude
import Blaze.UI.Types.HostBinaryPath (HostBinaryPath)
import Web.Scotty (Parsable(parseParam))
import qualified Data.UUID as UUID
import Database.Selda.SqlType ( Lit(LCustom)
                              , SqlTypeRep(TBlob)
                              , SqlType
                              )
import qualified Database.Selda.SqlType as Sql


newtype ClientId = ClientId UUID
  deriving (Eq, Ord, Read, Show, Generic)
  deriving anyclass (FromJSON, ToJSON, Hashable)

instance Parsable ClientId where
  parseParam = maybe (Left "Could not parse ClientId") (Right . ClientId)
    . UUID.fromText
    . cs

instance SqlType ClientId where
   mkLit (ClientId x) = LCustom TBlob $ Sql.mkLit x
   sqlType _ = TBlob
   fromSql x = ClientId $ Sql.fromSql x
   defaultValue = LCustom TBlob (Sql.defaultValue :: Lit UUID)

data SessionId = SessionId
  { clientId :: ClientId
  , hostBinaryPath :: HostBinaryPath
  }
  deriving (Eq, Ord, Show, Generic, Hashable, FromJSON, ToJSON)

mkSessionId :: ClientId -> HostBinaryPath -> SessionId
mkSessionId = SessionId
