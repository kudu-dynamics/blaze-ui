{-# LANGUAGE DataKinds #-}

module Blaze.UI.Types
  ( module Blaze.UI.Types
  , module WebMessages
  ) where

import Blaze.UI.Prelude
import qualified System.Envy as Envy
import System.Envy (fromEnv, FromEnv)
import qualified Data.HashMap.Strict as HashMap
import qualified Blaze.Types.Pil.Checker as Ch
import Blaze.Types.Pil (Stmt)
import qualified Binja.Function as BNFunc
import qualified Data.Aeson.Types as Aeson
import Blaze.UI.Types.WebMessages as WebMessages
import Blaze.Function (Function)
import Blaze.UI.Types.Cfg (CfgTransport, CfgId)
import Blaze.Types.Cfg (CfNode, CallNode, Cfg)
-- import Blaze.UI.Types.Cfg.Snapshot (BranchId, BranchTransport)
import qualified Blaze.UI.Types.Cfg.Snapshot as Snapshot
import Blaze.UI.Types.BinaryHash (BinaryHash)
import Blaze.UI.Types.Db (MonadDb(withDb))
import Database.Selda.SQLite (withSQLite)
import Blaze.UI.Types.BinaryManager (BinaryManager, BinaryManagerStorageDir(BinaryManagerStorageDir))
import Blaze.UI.Types.Session (SessionId, ClientId)
import Blaze.UI.Types.HostBinaryPath (HostBinaryPath)


data BinjaMessage a = BinjaMessage
  { clientId :: ClientId -- generated by client
  , hostBinaryPath :: HostBinaryPath
  -- , bndbHash :: BinaryHash -- obtain by uploading bndb to web server
  , action :: a
  } deriving (Eq, Ord, Show, Generic)

instance ToJSON a => ToJSON (BinjaMessage a)
instance FromJSON a => FromJSON (BinjaMessage a)

data ServerToBinja = SBLogInfo { message :: Text }
                   | SBLogWarn { message :: Text }
                   | SBLogError { message :: Text }

                   | SBCfg { cfgId :: CfgId
                           -- So plugin can easily warn if it's out of date
                           , bndbHash :: BinaryHash
                           -- TODO: send cfg with text
                           , cfg :: CfgTransport [Text]
                           }

                   | SBSnapshot { snapshotMsg :: Snapshot.ServerToBinja }
                     
                   | SBNoop
                   deriving (Eq, Ord, Show, Generic)

instance ToJSON ServerToBinja
instance FromJSON ServerToBinja


data BinjaToServer = BSConnect
                   | BSTextMessage { message :: Text }
                   | BSTypeCheckFunction { bndbHash :: BinaryHash
                                         , address :: Word64
                                         }

                   | BSCfgNew
                     { bndbHash :: BinaryHash
                     , startFuncAddress :: Word64
                     }
                   | BSCfgExpandCall
                     { cfgId :: CfgId
                     , callNode :: CallNode ()
                     }
                   | BSCfgRemoveBranch
                     { cfgId :: CfgId
                     , edge :: (CfNode (), CfNode ())
                     }

                   | BSCfgRemoveNode
                     { cfgId :: CfgId
                     , node :: CfNode ()
                     }

                   | BSSnapshot { snapshotMsg :: Snapshot.BinjaToServer }

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
  , sqliteFilePath :: FilePath
  , binaryManagerStorageDir :: BinaryManagerStorageDir
  } deriving (Eq, Ord, Show, Generic)

instance FromEnv ServerConfig where
  fromEnv _ = ServerConfig
    <$> Envy.env "BLAZE_UI_HOST"
    <*> Envy.env "BLAZE_UI_WS_PORT"
    <*> Envy.env "BLAZE_UI_HTTP_PORT"
    <*> Envy.env "BLAZE_UI_SQLITE_FILEPATH"
    <*> (BinaryManagerStorageDir <$> Envy.env "BLAZE_UI_BNDB_STORAGE_DIR")


data BlazeToServer = BZNoop
                   | BZImportantInteger Int
                   | BZTypeCheckFunctionReport BNFunc.Function Ch.TypeReport
                   | BZFunctionList [Function]
                   deriving (Eq, Ord, Show, Generic)

data Event = WebEvent WebToServer
           | BinjaEvent BinjaToServer
           deriving (Eq, Ord, Show, Generic)

-- TODO: Maybe we should just use SessionState since they are almost the same.
data EventLoopCtx = EventLoopCtx
  { clientId :: ClientId
  , hostBinaryPath :: HostBinaryPath
  , binaryManager :: BinaryManager
  , binjaOutboxes :: TVar (HashMap ThreadId (TQueue ServerToBinja))
  , webOutboxes :: TVar (HashMap ThreadId (TQueue ServerToWeb))
  , cfgs :: TVar (HashMap CfgId (TVar (Cfg [Stmt])))
  , sqliteFilePath :: FilePath
  } deriving (Generic)

data EventLoopState = EventLoopState
  { binjaOutput :: [ServerToBinja]
  , webOutput :: [ServerToWeb]
  } deriving (Generic)

data EventLoopError = EventLoopError Text
  deriving (Eq, Ord, Show, Generic)

newtype EventLoop a = EventLoop { _runEventLoop :: ReaderT EventLoopCtx (ExceptT EventLoopError IO) a }
  deriving newtype ( Functor
                   , Applicative
                   , Monad
                   , MonadReader EventLoopCtx
                   , MonadError EventLoopError
                   , MonadIO
                   , MonadThrow
                   , MonadCatch
                   , MonadMask
                   )

instance MonadDb EventLoop where
  withDb m = do
    ctx <- ask
    withSQLite (ctx ^. #sqliteFilePath) m

runEventLoop :: EventLoop a -> EventLoopCtx -> IO (Either EventLoopError a)
runEventLoop m ctx = runExceptT . flip runReaderT ctx $ _runEventLoop m

forkEventLoop :: EventLoop () -> EventLoop ThreadId
forkEventLoop m = ask >>= \ctx -> liftIO . forkIO . void $ runEventLoop m ctx

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
  { binaryPath :: HostBinaryPath
  , binaryManager :: BinaryManager
  , cfgs :: TVar (HashMap CfgId (TVar (Cfg [Stmt])))
  , binjaOutboxes :: TVar (HashMap ThreadId (TQueue ServerToBinja))
  , webOutboxes :: TVar (HashMap ThreadId (TQueue ServerToWeb))
  , eventHandlerThread :: TMVar ThreadId
  , eventInbox :: TQueue Event
  } deriving (Generic)

emptySessionState :: HostBinaryPath -> BinaryManager -> STM SessionState
emptySessionState binPath bm
  = SessionState binPath bm
    <$> newTVar HashMap.empty
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
