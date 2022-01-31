{- HLINT ignore "Use if" -}
{-# LANGUAGE DataKinds #-}

module Blaze.UI.Types
  ( module Blaze.UI.Types
  ) where

import Blaze.UI.Prelude
import qualified System.Envy as Envy
import System.Envy (fromEnv, FromEnv)
import qualified Data.HashMap.Strict as HashMap
import qualified Blaze.Types.Pil.Checker as Ch
import Blaze.Types.Pil (Stmt)
import qualified Binja.Function as BNFunc
import qualified Data.Aeson.Types as Aeson
import Blaze.Function (Function)
import Blaze.UI.Types.Cfg (CfgTransport, CfgId)
import qualified Blaze.UI.Types.Constraint as C
import Blaze.Types.Cfg (CfNode, CallNode, Cfg)
import qualified Blaze.UI.Types.Cfg.Snapshot as Snapshot
import qualified Blaze.UI.Types.Poi as Poi
import Blaze.UI.Types.Poi (Poi)
import Blaze.UI.Types.BinaryHash (BinaryHash)
import Blaze.UI.Types.Db (MonadDb(withDb))
import qualified Blaze.UI.Types.Db as Db
import Blaze.UI.Types.BinaryManager (BinaryManager, BinaryManagerStorageDir(BinaryManagerStorageDir))
import Blaze.UI.Types.Session (SessionId, ClientId)
import Blaze.UI.Types.HostBinaryPath (HostBinaryPath)
import Blaze.Pretty (Token)
import Blaze.Types.Cfg.Analysis (CallNodeRating, CallNodeRatingCtx)
import Blaze.UI.Types.CachedCalc (CachedCalc)
import System.Random (Random)


data BinjaMessage a = BinjaMessage
  { clientId :: ClientId -- generated by client
  , hostBinaryPath :: HostBinaryPath
  , action :: a
  } deriving (Eq, Ord, Show, Generic, FromJSON, ToJSON)

data PendingChanges = PendingChanges
  { removedNodes :: [UUID]
  , removedEdges :: [(UUID, UUID)]
  -- Maybe TODO: add "addedNodes" and "addedEdges"
  } deriving (Eq, Ord, Show, Generic, FromJSON, ToJSON)

data PoiSearchResults = PoiSearchResults
  { callNodeRatings :: [(UUID, CallNodeRating)]
  , presentTargetNodes :: [UUID]
  } deriving (Eq, Ord, Show, Generic, FromJSON, ToJSON)

data ServerToBinja = SBLogInfo { message :: Text }
                   | SBLogWarn { message :: Text }
                   | SBLogError { message :: Text }

                   | SBCfg { cfgId :: CfgId
                           -- So plugin can easily warn if it's out of date
                           , bndbHash :: BinaryHash
                           , poiSearchResults :: Maybe PoiSearchResults 
                           , pendingChanges :: Maybe PendingChanges
                           -- TODO: send cfg with text
                           , cfg :: CfgTransport [[Token]]
                           }

                   | SBSnapshot { snapshotMsg :: Snapshot.ServerToBinja }

                   | SBPoi { poiMsg :: Poi.ServerToBinja }

                   | SBConstraint { constraintMsg :: C.ServerToBinja }

                   | SBNoop
                   deriving (Eq, Ord, Show, Generic, FromJSON, ToJSON)

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
                     , targetAddress :: Word64
                     }
                   | BSCfgRemoveBranch
                     { cfgId :: CfgId
                     , edge :: (CfNode (), CfNode ())
                     }
                   | BSCfgRemoveNode
                     { cfgId :: CfgId
                     , node :: CfNode ()
                     }
                   | BSCfgFocus
                     { cfgId :: CfgId
                     , node :: CfNode ()
                     }

                   | BSCfgConfirmChanges
                     { cfgId :: CfgId }

                   | BSCfgRevertChanges
                     { cfgId :: CfgId }

                   | BSSnapshot { snapshotMsg :: Snapshot.BinjaToServer }

                   | BSPoi { poiMsg :: Poi.BinjaToServer }

                   | BSConstraint { constraintMsg :: C.BinjaToServer }

                   | BSComment
                     { cfgId :: CfgId
                     , nodeId :: UUID
                     , stmtIndex :: Word64
                     , comment :: Text
                     }

                   | BSNoop

                   deriving (Eq, Ord, Show, Generic, FromJSON, ToJSON)

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

newtype Event = BinjaEvent BinjaToServer
              deriving (Eq, Ord, Show, Generic)

-- TODO: Maybe we should just use SessionState since they are almost the same.
data EventLoopCtx = EventLoopCtx
  { clientId :: ClientId
  , hostBinaryPath :: HostBinaryPath
  , binaryManager :: BinaryManager
  , binjaOutboxes :: TVar BinjaOutboxes
  , cfgs :: TVar (HashMap CfgId (TVar (Cfg [Stmt])))
  , dbConn :: TMVar Db.Conn
  , activePoi :: TVar (Maybe Poi)
  , callNodeRatingCtx :: CachedCalc BinaryHash CallNodeRatingCtx
  } deriving (Generic)

newtype EventLoopState = EventLoopState
  { binjaOutput :: [ServerToBinja]
  } deriving (Generic)

newtype EventLoopError = EventLoopError Text
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
    tconn <- view #dbConn <$> ask
    conn <- liftIO . atomically $ takeTMVar tconn
    r <- Db.runSelda conn m
    liftIO . atomically $ putTMVar tconn conn
    return r

runEventLoop :: EventLoop a -> EventLoopCtx -> IO (Either EventLoopError a)
runEventLoop m ctx = runExceptT . flip runReaderT ctx $ _runEventLoop m

forkEventLoop :: EventLoop () -> EventLoop ThreadId
forkEventLoop m = ask >>= \ctx -> liftIO . forkIO . void $ runEventLoop m ctx

forkEventLoop_ :: EventLoop () -> EventLoop ()
forkEventLoop_ = void . forkEventLoop

debug :: Text -> EventLoop ()
debug =  putText

type BinjaOutboxes = HashMap ConnId (ThreadId, TQueue ServerToBinja)
  
-- there are multiple outboxes in case there are multiple conns to same binary
data SessionState = SessionState
  { binaryPath :: HostBinaryPath
  , binaryManager :: BinaryManager
  , cfgs :: TVar (HashMap CfgId (TVar (Cfg [Stmt])))
  , binjaOutboxes :: TVar BinjaOutboxes
  , eventHandlerThread :: TMVar ThreadId
  , eventInbox :: TQueue Event
  , dbConn :: TMVar Db.Conn
  , activePoi :: TVar (Maybe Poi)
  , callNodeRatingCtx :: CachedCalc BinaryHash CallNodeRatingCtx
  } deriving (Generic)

emptySessionState
  :: HostBinaryPath
  -> BinaryManager
  -> TMVar Db.Conn
  -> CachedCalc BinaryHash CallNodeRatingCtx
  -> STM SessionState
emptySessionState binPath bm tconn ccCallRating
  = SessionState binPath bm
    <$> newTVar HashMap.empty
    <*> newTVar HashMap.empty
    <*> newEmptyTMVar
    <*> newTQueue
    <*> return tconn
    <*> newTVar Nothing
    <*> return ccCallRating

newtype ConnId = ConnId UUID
  deriving (Eq, Ord, Show, Generic)
  deriving newtype (Hashable, Random)

newConnId :: IO ConnId
newConnId = randomIO

-- all the changeable fields should be STM vars
-- so this can be updated across threads
data AppState = AppState
  { serverConfig :: ServerConfig
  , binarySessions :: TVar (HashMap SessionId SessionState)
  -- Session Conns are used to see when a session has no more conns and can be cleaned up
  , sessionConns :: TVar (HashMap ConnId SessionId)
  , dbConn :: TMVar Db.Conn
  } deriving (Generic)

-- | Inserts a unique ConnId for a SessionId.
-- SessionIds can have multiple active connections if a single user opens multiple
-- copies of a BNDB.
addSessionConn :: SessionId -> ConnId -> AppState -> STM ()
addSessionConn sid cid st =
  readTVar tv >>= writeTVar tv . HashMap.insert cid sid
  where
    tv = st ^. #sessionConns

-- | Removes ConnId from the binja outboxes in SessionState.
-- Returns thread id of binja outbox, if it exists, and updated BinjaOutboxes map
-- Mutatively sets the new map in the SessionState
cleanupBinjaOutbox :: ConnId -> SessionState -> STM (Maybe ThreadId, BinjaOutboxes)
cleanupBinjaOutbox connId ss = do
  binjaOutboxMap <- readTVar $ ss ^. #binjaOutboxes
  case HashMap.lookup connId binjaOutboxMap of
    Nothing -> return (Nothing, binjaOutboxMap)
    Just (bthreadId, _) -> do
      let binjaOutboxMap' = HashMap.delete connId binjaOutboxMap
      writeTVar (ss ^. #binjaOutboxes) binjaOutboxMap'
      return (Just bthreadId, binjaOutboxMap')

-- | Removes ConnId from all sessions and frees up sessions with no active connections.
cleanupClosedConn :: ConnId -> AppState -> IO ()
cleanupClosedConn cid st = do
  threads <- atomically $ do
    sconns <- readTVar $ st ^. #sessionConns
    case HashMap.lookup cid sconns of
      Nothing -> return []
      Just sid -> do
        writeTVar (st ^. #sessionConns) $ HashMap.delete cid sconns
        binSessions <- readTVar $ st ^. #binarySessions
        case HashMap.lookup sid binSessions of
          Nothing -> return []
          Just ss -> do
            (mBinjaOutboxThread, binjaOutboxMap) <- cleanupBinjaOutbox cid ss
            let bthreads = maybeToList mBinjaOutboxThread
            case HashMap.null binjaOutboxMap of
              False -> return bthreads
              True -> do
                mEventThread <- tryReadTMVar $ ss ^. #eventHandlerThread
                writeTVar (st ^. #binarySessions) $ HashMap.delete sid binSessions
                return $ bthreads <> maybeToList mEventThread
  putText $ "Killed " <> show (length threads) <> " threads"
  mapM_ killThread threads

initAppState :: ServerConfig -> Db.Conn -> IO AppState
initAppState cfg' conn = AppState cfg'
  <$> newTVarIO HashMap.empty
  <*> newTVarIO HashMap.empty
  <*> newTMVarIO conn

lookupSessionState :: SessionId -> AppState -> STM (Maybe SessionState)
lookupSessionState sid st = do
  m <- readTVar $ st ^. #binarySessions
  return $ HashMap.lookup sid m
