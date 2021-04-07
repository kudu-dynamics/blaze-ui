{-# LANGUAGE DataKinds #-}

module Blaze.UI.Types
  ( module Blaze.UI.Types
  , module WebMessages
  ) where

import Blaze.UI.Prelude
import qualified System.Envy as Envy
import System.Envy (fromEnv, FromEnv)
import Binja.Core (BNBinaryView)
import qualified Data.HashMap.Strict as HashMap
import Web.Scotty (Parsable(parseParam))
import Data.Text.Encoding.Base64.URL (encodeBase64, decodeBase64)
import qualified Blaze.Types.Pil.Checker as Ch
import Blaze.Types.Pil (Stmt)
import qualified Binja.Function as BNFunc
import qualified Data.Aeson.Types as Aeson
import Blaze.UI.Types.WebMessages as WebMessages
import Blaze.Function (Function)
import Blaze.UI.Types.Cfg (CfgTransport, CfgId)
import Blaze.Types.Cfg (CfNode, CallNode, Cfg)

data BinjaMessage a = BinjaMessage
  { bvFilePath :: Text
  , action :: a
  } deriving (Eq, Ord, Show, Generic)

instance ToJSON a => ToJSON (BinjaMessage a)
instance FromJSON a => FromJSON (BinjaMessage a)

data ServerToBinja = SBLogInfo { message :: Text }
                   | SBLogWarn { message :: Text }
                   | SBLogError { message :: Text }

                   | SBCfg { cfgId :: CfgId
                           -- TODO: send cfg with text
                           , cfg :: CfgTransport [Text]
                           }
                   
                   | SBNoop
                   deriving (Eq, Ord, Show, Generic)

instance ToJSON ServerToBinja
instance FromJSON ServerToBinja


data BinjaToServer = BSConnect
                   | BSTextMessage { message :: Text }
                   | BSTypeCheckFunction { address :: Word64 }

                   | BSCfgNew
                     { startFuncAddress :: Word64
                     }
                   | BSCfgExpandCall
                     { cfgId :: CfgId
                     , callNode :: CallNode ()
                     }
                   | BSCfgRemoveBranch
                     { cfgId :: CfgId
                     , edge :: (CfNode (), CfNode ())
                     }

                   | BSNoop

                   deriving (Eq, Ord, Show, Generic)

instance ToJSON BinjaToServer
instance FromJSON BinjaToServer

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


webOptions :: Aeson.Options
webOptions = Aeson.defaultOptions
             { Aeson.unwrapUnaryRecords = True
             , Aeson.tagSingleConstructors = True
             }

data ServerConfig = ServerConfig
  { serverHost :: Text
  , serverWsPort :: Int
  , serverHttpPort :: Int
  } deriving (Eq, Ord, Show, Generic)

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
                   | BZTypeCheckFunctionReport BNFunc.Function Ch.TypeReport
                   | BZFunctionList [Function]
                   deriving (Eq, Ord, Show, Generic)

data Event = WebEvent WebToServer
           | BinjaEvent BinjaToServer
           deriving (Eq, Ord, Show, Generic)


data EventLoopCtx = EventLoopCtx
  { binjaOutboxes :: TVar (HashMap ThreadId (TQueue ServerToBinja))
  , webOutboxes :: TVar (HashMap ThreadId (TQueue ServerToWeb))
  , cfgs :: TVar (HashMap CfgId (TVar (Cfg [Stmt])))
  } deriving (Generic)

data EventLoopState = EventLoopState
  { binjaOutput :: [ServerToBinja]
  , webOutput :: [ServerToWeb]
  } deriving (Generic)

newtype EventLoop a = EventLoop { _runEventLoop :: ReaderT EventLoopCtx IO a }
  deriving newtype ( Functor
                   , Applicative
                   , Monad
                   , MonadReader EventLoopCtx
                   , MonadIO
                   )

runEventLoop :: EventLoop a -> EventLoopCtx -> IO a
runEventLoop m ctx = flip runReaderT ctx $ _runEventLoop m

forkEventLoop :: EventLoop () -> EventLoop ThreadId
forkEventLoop m = ask >>= \ctx -> liftIO . forkIO $ runEventLoop m ctx

forkEventLoop_ :: EventLoop () -> EventLoop ()
forkEventLoop_ = void . forkEventLoop

debug :: Text -> EventLoop ()
debug =  putText

-- -- shared across sessions
-- data ChallengeState = ChallengeState
--   { icfgs :: TVar (HashMap CfgId (TVar CfgState))
--   }

-- there are multiple outboxes in case there are multiple conns to same binary
data SessionState = SessionState
  { binaryPath :: Maybe Text
  , binaryView :: TMVar BNBinaryView
  , cfgs :: TVar (HashMap CfgId (TVar (Cfg [Stmt])))
  , binjaOutboxes :: TVar (HashMap ThreadId (TQueue ServerToBinja))
  , webOutboxes :: TVar (HashMap ThreadId (TQueue ServerToWeb))
  , eventHandlerThread :: TMVar ThreadId
  , eventInbox :: TQueue Event
  } deriving (Generic)

emptySessionState :: Maybe Text -> STM SessionState
emptySessionState binPath
  = SessionState binPath
    <$> newEmptyTMVar
    <*> newTVar HashMap.empty
    <*> newTVar HashMap.empty
    <*> newTVar HashMap.empty
    <*> newEmptyTMVar
    <*> newTQueue

-- all the changeable fields should be STM vars
-- so this can be updated across threads
data AppState = AppState
  { serverConfig :: ServerConfig
  , binarySessions :: TVar (HashMap SessionId SessionState)
  } deriving (Generic)

-- not really empty...
emptyAppState :: ServerConfig -> IO AppState
emptyAppState cfg' = AppState cfg' <$> newTVarIO HashMap.empty

lookupSessionState :: SessionId -> AppState -> STM (Maybe SessionState)
lookupSessionState sid st = do
  m <- readTVar $ st ^. #binarySessions
  return $ HashMap.lookup sid m


addCfg :: CfgId -> Cfg [Stmt] -> EventLoop ()
addCfg cid cfg' = do
  cfgMapTVar <- view #cfgs <$> ask
  liftIO . atomically $ do
    m <- readTVar cfgMapTVar
    case HashMap.lookup cid m of
      Nothing -> do
        cfgTVar <- newTVar cfg'
        writeTVar cfgMapTVar $ HashMap.insert cid cfgTVar m
      Just cfgTMVar -> do
        writeTVar cfgTMVar cfg'
  return ()

getCfg :: CfgId -> EventLoop (Maybe (Cfg [Stmt]))
getCfg cid = do
  cfgMapTVar <- view #cfgs <$> ask
  liftIO . atomically $ do
    m <- readTVar cfgMapTVar
    maybe (return Nothing) (fmap Just . readTVar) $ HashMap.lookup cid m
