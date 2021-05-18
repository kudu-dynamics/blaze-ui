module Blaze.UI.Types.Session where

import Blaze.UI.Prelude
import Blaze.UI.Types.HostBinaryPath (HostBinaryPath)
import Web.Scotty (Parsable(parseParam))
import qualified Data.UUID as UUID

newtype ClientId = ClientId UUID
  deriving (Eq, Ord, Read, Show, Generic)
  deriving anyclass (FromJSON, ToJSON, Hashable)

instance Parsable ClientId where
  parseParam = maybe (Left "Could not parse ClientId") (Right . ClientId)
    . UUID.fromText
    . cs

data SessionId = SessionId
  { clientId :: ClientId
  , hostBinaryPath :: HostBinaryPath
  }
  deriving (Eq, Ord, Show, Generic, Hashable, FromJSON, ToJSON)
