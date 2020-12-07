{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TemplateHaskell #-}
module Blaze.UI.Types where

import Blaze.UI.Prelude
import qualified System.Envy as Envy
import System.Envy (fromEnv, FromEnv)
import Binja.Core (BNBinaryView)
import qualified Data.HashMap.Strict as HashMap
import Web.Scotty (Parsable(parseParam))
import Data.Text.Encoding.Base64.URL (encodeBase64, decodeBase64)
import qualified Blaze.Types.Pil.Checker as Ch
import Binja.Function (Function)
import qualified Data.Aeson.Types as Aeson
import qualified Language.PureScript.Bridge as PB
import qualified Blaze.Types.CallGraph as CG
import qualified Language.PureScript.Bridge.CodeGenSwitches as S

data BinjaMessage a = BinjaMessage
  { _bvFilePath :: Text
  , _action :: a
  } deriving (Eq, Ord, Show, Generic)
$(makeFieldsNoPrefix ''BinjaMessage)

instance ToJSON a => ToJSON (BinjaMessage a)
instance FromJSON a => FromJSON (BinjaMessage a)

data ServerToBinja = SBLogInfo { message :: Text }
                   | SBLogWarn { message :: Text }
                   | SBLogError { message :: Text }
                   | SBNoop
                   deriving (Eq, Ord, Show, Generic)

instance ToJSON ServerToBinja
instance FromJSON ServerToBinja


data BinjaToServer = BSConnect
                   | BSTextMessage { message :: Text }
                   | BSTypeCheckFunction { address :: Word64 }
                   | BSNoop
                   deriving (Eq, Ord, Show, Generic)

instance ToJSON BinjaToServer
instance FromJSON BinjaToServer

data WebToServer = WSTextMessage { message :: Text }
                 | WSNoop
                 deriving (Eq, Ord, Show, Generic)

instance ToJSON WebToServer
instance FromJSON WebToServer

data FunctionDescriptor = FunctionDescriptor
  { name :: Text
  , address :: Int
  } deriving (Eq, Ord, Show, Generic)

instance ToJSON FunctionDescriptor
instance FromJSON FunctionDescriptor

newtype SWLogErrorArgs = SWLogErrorArgs { message :: Maybe Text }
  deriving (Eq, Ord, Show, Generic)

instance ToJSON SWLogErrorArgs
instance FromJSON SWLogErrorArgs

data ServerToWeb = SWTextMessage { message :: Text }
                 | SWLogInfo { message :: Text }
                 | SWLogWarn { mmessage :: Maybe Text }
                 | SWLogError SWLogErrorArgs
                 | SWNoop
                 | SWFunctionsList { functions :: [CG.Function] }
                 deriving (Eq, Ord, Show, Generic, ToJSON, FromJSON)

webOptions :: Aeson.Options
webOptions = Aeson.defaultOptions
             { Aeson.unwrapUnaryRecords = True
             , Aeson.tagSingleConstructors = True
             }


-- instance ToJSON ServerToWeb where
--     toEncoding = Aeson.genericToEncoding webOptions

-- instance ToJSON ServerToWeb
-- instance FromJSON ServerToWeb

myTypes :: [PB.SumType 'PB.Haskell]
myTypes =
  [ let p = (Proxy :: Proxy ServerToWeb) in
      PB.order p (PB.mkSumType p)
  , let p = (Proxy :: Proxy SWLogErrorArgs) in
      PB.order p (PB.mkSumType p)
  , let p = (Proxy :: Proxy CG.Function) in
      PB.order p (PB.mkSumType p)
  ]


tryPB :: IO ()
tryPB = do
  let s = S.useGenRep <> S.genForeign (S.ForeignOptions True) <> S.genLenses
  PB.writePSTypesWith s "/tmp/jobo" (PB.buildBridge PB.defaultBridge) myTypes

data ServerConfig = ServerConfig
  { serverHost :: Text
  , serverWsPort :: Int
  , serverHttpPort :: Int
  } deriving (Eq, Ord, Show)

instance FromEnv ServerConfig where
  fromEnv _ = ServerConfig
    <$> Envy.env "BLAZE_UI_HOST"
    <*> Envy.env "BLAZE_UI_WS_PORT"
    <*> Envy.env "BLAZE_UI_HTTP_PORT"

newtype SessionId = SessionId Text
  deriving (Eq, Ord, Show, Generic)

instance Hashable SessionId
instance Parsable SessionId where
  parseParam = Right . SessionId . cs

binaryPathToSessionId :: Text -> SessionId
binaryPathToSessionId = SessionId . encodeBase64

sessionIdToBinaryPath :: SessionId -> Either Text Text
sessionIdToBinaryPath (SessionId x) = decodeBase64 x

data BlazeToServer = BZNoop
                   | BZImportantInteger Int
                   | BZTypeCheckFunctionReport Function Ch.TypeReport
                   deriving (Eq, Ord, Show, Generic)

data Event = WebEvent WebToServer
           | BinjaEvent BinjaToServer
           | BlazeEvent BlazeToServer
           deriving (Eq, Ord, Show, Generic)

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

nonAsyncIO :: IO a -> EventLoop a
nonAsyncIO = EventLoop . liftIO

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
  

    

