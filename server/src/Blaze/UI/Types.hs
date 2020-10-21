{-# LANGUAGE TemplateHaskell #-}
module Blaze.UI.Types where

import Blaze.UI.Prelude
import Data.Aeson (FromJSON, ToJSON)
import qualified System.Envy as Envy
import System.Envy (fromEnv, FromEnv)
import Control.Concurrent.STM.TQueue (newTQueueIO, TQueue, readTQueue, newTQueue)
import Control.Concurrent.STM.TVar (newTVarIO, TVar, readTVar, newTVar)
import Control.Concurrent.STM.TMVar (TMVar, readTMVar, newEmptyTMVar)
import Binja.Core (BNBinaryView)
import qualified Web.Hashids as Hashids
import qualified Data.HashMap.Strict as HashMap

data BinjaMessage a = BinjaMessage
  { _bvFilePath :: Text
  , _action :: a
  } deriving (Eq, Ord, Read, Show, Generic)
$(makeFieldsNoPrefix ''BinjaMessage)

instance ToJSON a => ToJSON (BinjaMessage a)
instance FromJSON a => FromJSON (BinjaMessage a)

data ServerToBinja = SBTextMessage { message :: Text }
                   | SBLogInfo { message :: Text }
                   | SBLogWarn { message :: Text }
                   | SBLogError { message :: Text }
                   | SBNoop
                   | SBBadMoney { name :: Text, age :: Int}
                   deriving (Eq, Ord, Read, Show, Generic)

instance ToJSON ServerToBinja
instance FromJSON ServerToBinja


data BinjaToServer = BSConnect
                   | BSTextMessage { message :: Text }
                   | BSNoop
                   | BSBadMoney { name :: Text, age :: Int}
                   deriving (Eq, Ord, Read, Show, Generic)

instance ToJSON BinjaToServer
instance FromJSON BinjaToServer

data WebToServer = WSTextMessage { message :: Text }
                 | WSNoop
                 deriving (Eq, Ord, Read, Show, Generic)

instance ToJSON WebToServer
instance FromJSON WebToServer

data ServerToWeb = SWTextMessage { message :: Text }
                 | SWNoop
                 deriving (Eq, Ord, Read, Show, Generic)

instance ToJSON ServerToWeb
instance FromJSON ServerToWeb


data ServerConfig = ServerConfig
  { serverHost :: Text
  , serverPort :: Int
  } deriving (Eq, Ord, Read, Show)

instance FromEnv ServerConfig where
  fromEnv _ = ServerConfig
    <$> Envy.env "BLAZE_UI_HOST"
    <*> Envy.env "BLAZE_UI_PORT"

newtype SessionId = SessionId ByteString
  deriving (Eq, Ord, Read, Show, Generic)

instance Hashable SessionId

binaryPathToSessionId :: Text -> SessionId
binaryPathToSessionId = SessionId . Hashids.encode ctx . hash
  where
    ctx = Hashids.hashidsMinimum "Make sure your salt is fortified with iodine" 8


data BlazeToServer = BzSNoop
                   deriving (Eq, Ord, Read, Show, Generic)

data Event = WebEvent WebToServer
           | BinjaEvent BinjaToServer
           | BlazeEvent BlazeToServer
           deriving (Eq, Ord, Read, Show, Generic)

data EventLoopState = EventLoopState
  { _binjaOutput :: [ServerToBinja]
  , _webOutput :: [ServerToWeb]
  , _blazeActions :: [IO BlazeToServer]
  , _binaryView :: BNBinaryView
  }
$(makeFieldsNoPrefix ''EventLoopState)

newtype EventLoop a = EventLoop { _runEventLoop :: StateT EventLoopState IO a }
  deriving newtype ( Functor, Applicative, Monad, MonadState EventLoopState )

sendToBinja :: ServerToBinja -> EventLoop ()
sendToBinja ax = binjaOutput %= (ax:)

sendToWeb :: ServerToWeb -> EventLoop ()
sendToWeb ax = webOutput %= (ax:)

doAction :: IO BlazeToServer -> EventLoop ()
doAction ax = blazeActions %= (ax:)

-- there are multiple outboxes in case there are multiple conns to same binary
data SessionState = SessionState
  { _binaryView :: TMVar BNBinaryView
  , _binjaOutboxes :: TVar (HashMap ThreadId (TQueue ServerToBinja))
  , _webOutboxes :: TVar (HashMap ThreadId (TQueue ServerToWeb))
  , _eventHandlerThread :: TMVar ThreadId
  , _eventInbox :: TQueue Event
  , _blazeActions :: TQueue (IO BlazeToServer)
  }
$(makeFieldsNoPrefix ''SessionState)

emptySessionState :: STM SessionState
emptySessionState = SessionState <$> newEmptyTMVar
                                 <*> newTVar HashMap.empty
                                 <*> newTVar HashMap.empty
                                 <*> newEmptyTMVar
                                 <*> newTQueue
                                 <*> newTQueue

-- all the changeable fields should be STM vars
-- so this can be updated across threads
data AppState = AppState
  { _binarySessions :: TVar (HashMap SessionId SessionState) }
$(makeFieldsNoPrefix ''AppState)

emptyAppState :: IO AppState
emptyAppState = AppState <$> newTVarIO HashMap.empty

lookupSessionState :: SessionId -> AppState -> STM (Maybe SessionState)
lookupSessionState sid st = do
  m <- readTVar $ st ^. binarySessions
  return $ HashMap.lookup sid m
  

    

