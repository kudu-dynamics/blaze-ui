module Blaze.UI.Server where

import Blaze.UI.Prelude
import qualified Prelude as P
import Data.Aeson (FromJSON, ToJSON)
import qualified Data.Aeson as Aeson
import qualified Network.WebSockets as WS
import qualified System.Envy as Envy
import System.Envy (fromEnv, FromEnv)
import qualified Data.ByteString.Lazy as LBS

data BlazeMessage = TextMessage { message :: Text }
                  | Noop
                  | BadMoney { name :: Text, age :: Int}
                  deriving (Eq, Ord, Read, Show, Generic)

instance ToJSON BlazeMessage
instance FromJSON BlazeMessage


data ServerConfig = ServerConfig
  { serverHost :: Text
  , serverPort :: Int
  } deriving (Eq, Ord, Read, Show)

instance FromEnv ServerConfig where
  fromEnv _ = ServerConfig
    <$> Envy.env "BLAZE_UI_SERVER_HOST"
    <*> Envy.env "BLAZE_UI_SERVER_PORT"

receiveJSON :: FromJSON a => WS.Connection -> IO (Either Text a)
receiveJSON conn = do
  x <- WS.receiveData conn :: IO LBS.ByteString
  return . first cs . Aeson.eitherDecode $ x

sendJSON :: ToJSON a => WS.Connection -> a -> IO ()
sendJSON conn x =
  WS.sendTextData conn(Aeson.encode x :: LBS.ByteString)

app :: WS.PendingConnection -> IO ()
app pconn = WS.acceptRequest pconn >>= loop
  where
    loop conn = do
      er <- receiveJSON conn :: IO (Either Text BlazeMessage)
      case er of
        Left err -> do
          putText $ "Error parsing JSON: " <> show err
        Right x -> do
          putText $ "Got message: " <> show x
          sendJSON conn . TextMessage $ "I got your message, loser."
      loop conn

run :: ServerConfig -> IO ()
run cfg =
  WS.runServer (cs $ serverHost cfg) (serverPort cfg) app



main :: IO ()
main = (Envy.decodeEnv :: IO (Either String ServerConfig))
  >>= either P.error run
  


testClient :: BlazeMessage -> WS.Connection -> IO BlazeMessage
testClient msg conn = do
  sendJSON conn msg
  (Right r) <- receiveJSON conn
  return r

runClient :: ServerConfig -> (WS.Connection -> IO a) -> IO a
runClient cfg = WS.runClient (cs $ serverHost cfg) (serverPort cfg) ""
