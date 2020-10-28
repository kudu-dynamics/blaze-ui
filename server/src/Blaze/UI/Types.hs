{-# LANGUAGE TemplateHaskell #-}
module Blaze.UI.Types where

import Blaze.UI.Prelude
import qualified Prelude as P
import Data.Aeson (FromJSON, ToJSON)
import qualified System.Envy as Envy
import System.Envy (fromEnv, FromEnv)
import Control.Concurrent.STM.TQueue (newTQueueIO, TQueue, readTQueue, newTQueue)
import Control.Concurrent.STM.TVar (newTVarIO, TVar, readTVar, newTVar)
import Control.Concurrent.STM.TMVar (TMVar, readTMVar, newEmptyTMVar)
import Binja.Core (BNBinaryView)
import qualified Web.Hashids as Hashids
import qualified Data.HashMap.Strict as HashMap
import Web.Scotty (Parsable(parseParam))
import Data.Text.Encoding.Base64.URL (encodeBase64, decodeBase64)

data BinjaMessage a = BinjaMessage
  { _bvFilePath :: Text
  , _action :: a
  } deriving (Eq, Ord, Read, Show, Generic)
$(makeFieldsNoPrefix ''BinjaMessage)

instance ToJSON a => ToJSON (BinjaMessage a)
instance FromJSON a => FromJSON (BinjaMessage a)

data ServerToBinja = SBLogInfo { message :: Text }
                   | SBLogWarn { message :: Text }
                   | SBLogError { message :: Text }
                   | SBNoop
                   deriving (Eq, Ord, Read, Show, Generic)

instance ToJSON ServerToBinja
instance FromJSON ServerToBinja


data BinjaToServer = BSConnect
                   | BSTextMessage { message :: Text }
                   | BSNoop
                   deriving (Eq, Ord, Read, Show, Generic)

instance ToJSON BinjaToServer
instance FromJSON BinjaToServer

data WebToServer = WSTextMessage { message :: Text }
                 | WSNoop
                 deriving (Eq, Ord, Read, Show, Generic)

instance ToJSON WebToServer
instance FromJSON WebToServer

data ServerToWeb = SWTextMessage { message :: Text }
                 | SWLogInfo { message :: Text }
                 | SWLogWarn { message :: Text }
                 | SWLogError { message :: Text }
                 | SWNoop
                 deriving (Eq, Ord, Read, Show, Generic)

instance ToJSON ServerToWeb
instance FromJSON ServerToWeb


data ServerConfig = ServerConfig
  { serverHost :: Text
  , serverWsPort :: Int
  , serverHttpPort :: Int
  } deriving (Eq, Ord, Read, Show)

instance FromEnv ServerConfig where
  fromEnv _ = ServerConfig
    <$> Envy.env "BLAZE_UI_HOST"
    <*> Envy.env "BLAZE_UI_WS_PORT"
    <*> Envy.env "BLAZE_UI_HTTP_PORT"

newtype SessionId = SessionId Text
  deriving (Eq, Ord, Read, Show, Generic)

instance Hashable SessionId
instance Parsable SessionId where
  parseParam = Right . SessionId . cs

binaryPathToSessionId :: Text -> SessionId
binaryPathToSessionId = SessionId . encodeBase64

sessionIdToBinaryPath :: SessionId -> Either Text Text
sessionIdToBinaryPath (SessionId x) = decodeBase64 x

data BlazeToServer = BZNoop
                   | BZImportantInteger Int
                   deriving (Eq, Ord, Read, Show, Generic)

data Event = WebEvent WebToServer
           | BinjaEvent BinjaToServer
           | BlazeEvent BlazeToServer
           deriving (Eq, Ord, Read, Show, Generic)

data EventLoopState = EventLoopState
  { _binjaOutput :: [ServerToBinja]
  , _webOutput :: [ServerToWeb]
  , _blazeActions :: [IO BlazeToServer]
  }
$(makeFieldsNoPrefix ''EventLoopState)

-- IO is in EventLoop only for debugging.
newtype EventLoop a = EventLoop { _runEventLoop :: StateT EventLoopState IO a }
  deriving newtype ( Functor, Applicative, Monad, MonadState EventLoopState )

runEventLoop :: EventLoop a -> EventLoopState -> IO (a, EventLoopState)
runEventLoop m s = flip runStateT s $ _runEventLoop m

debug :: Text -> EventLoop ()
debug = EventLoop . putText

sendToBinja :: ServerToBinja -> EventLoop ()
sendToBinja ax = binjaOutput %= (ax:)

sendToWeb :: ServerToWeb -> EventLoop ()
sendToWeb ax = webOutput %= (ax:)

doAction :: IO BlazeToServer -> EventLoop ()
doAction ax = blazeActions %= (ax:)

-- there are multiple outboxes in case there are multiple conns to same binary
data SessionState = SessionState
  { _binaryPath :: Maybe Text
  , _binaryView :: TMVar BNBinaryView
  , _binjaOutboxes :: TVar (HashMap ThreadId (TQueue ServerToBinja))
  , _webOutboxes :: TVar (HashMap ThreadId (TQueue ServerToWeb))
  , _eventHandlerThread :: TMVar ThreadId
  , _eventInbox :: TQueue Event
  , _blazeActions :: TQueue (IO BlazeToServer)
  , _blazeActionHandlerThread :: TMVar ThreadId
  }
$(makeFieldsNoPrefix ''SessionState)

emptySessionState :: Maybe Text -> STM SessionState
emptySessionState binPath
  = SessionState binPath
    <$> newEmptyTMVar
    <*> newTVar HashMap.empty
    <*> newTVar HashMap.empty
    <*> newEmptyTMVar
    <*> newTQueue
    <*> newTQueue
    <*> newEmptyTMVar

-- all the changeable fields should be STM vars
-- so this can be updated across threads
data AppState = AppState
  { _serverConfig :: ServerConfig
  , _binarySessions :: TVar (HashMap SessionId SessionState) }
$(makeFieldsNoPrefix ''AppState)

-- not really empty...
emptyAppState :: ServerConfig -> IO AppState
emptyAppState cfg = AppState cfg <$> newTVarIO HashMap.empty

lookupSessionState :: SessionId -> AppState -> STM (Maybe SessionState)
lookupSessionState sid st = do
  m <- readTVar $ st ^. binarySessions
  return $ HashMap.lookup sid m
  

    

