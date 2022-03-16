{- HLINT ignore "Use if" -}
{-# LANGUAGE DataKinds #-}
{-# OPTIONS_GHC -Wno-unrecognised-pragmas #-}

-----------------------------------------------------------------------------
-- |
-- Module      :  Blaze.UI.Types
-- Copyright   :  (c) Kudu Dynamics, 2022
-- License     :
--
-- Maintainer  :
-- Stability   :  experimental
-- Portability :
--
-- The Blaze UI server manages websocket connections from BinaryNinja Plugin clients
-- and runs analysis using Blaze. There is also a webserver used to POST binary data
-- and submit POIs.
--
-- Each `SessionId` corresponds to a bndb path and clientId combo. There exists
-- one `SessionState` for each `SessionId`.
--
-- A client can open multiple connections to the same bndb using multiple tabs or
-- instances of BinaryNinja, but they will share the same `SessionState`
-- and any actions performed in one window will affect the state, such as the
-- ICFG view or POI list, of the Blaze plugin in any other windows.

-----------------------------------------------------------------------------

module Blaze.UI.Types
  ( module Blaze.UI.Types
  ) where

import Blaze.UI.Prelude
import qualified System.Envy as Envy
import System.Envy (fromEnv, FromEnv)
import qualified Data.HashMap.Strict as HashMap
import qualified Data.HashSet as HashSet
import qualified Blaze.Types.Pil.Checker as Ch
import Blaze.Types.Pil (Stmt)
import qualified Binja.Function as BNFunc
import qualified Data.Aeson.Types as Aeson
import Blaze.Function (Function)
import Blaze.UI.Types.Cfg (CfgTransport, CfgId)
import qualified Blaze.UI.Types.Constraint as C
import Blaze.Types.Cfg (CallNode)
import qualified Blaze.Types.Cfg as Cfg
import Blaze.Types.Cfg.Grouping (Cfg, CfNode)
import qualified Blaze.UI.Types.Cfg.Snapshot as Snapshot
import qualified Blaze.UI.Types.Poi as Poi
import Blaze.UI.Types.Poi (Poi)
import Blaze.UI.Types.BndbHash (BndbHash)
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
import qualified Network.WebSockets as WS

-- | This meta message wraps every message between the server and BinaryNinja plugin.
-- The `clientId` and `hostBinaryPath` are provided by the client.
data BinjaMessage a = BinjaMessage
  { clientId :: ClientId
  , hostBinaryPath :: HostBinaryPath
  , binaryHash :: BinaryHash
  , action :: a
  } deriving (Eq, Ord, Show, Generic, FromJSON, ToJSON, Hashable)

-- | When an ICFG action, such as prune or focus, is requested, we show the user
-- the nodes and edges that will be removed if the action is performed.
data PendingChanges = PendingChanges
  { removedNodes :: [UUID]
  , removedEdges :: [(UUID, UUID)]
  } deriving (Eq, Ord, Show, Generic, FromJSON, ToJSON, Hashable)

-- | The ranked results of a POI search, showing the call nodes that will most
-- quickly reach the POI.
data PoiSearchResults = PoiSearchResults
  { callNodeRatings :: [(UUID, CallNodeRating)]
  , presentTargetNodes :: [UUID]
  } deriving (Eq, Ord, Show, Generic, FromJSON, ToJSON, Hashable)

-- | Candidate group end nodes that will be shown to the user. The user may
-- select one of these to finish defining a group.
data GroupOptions = GroupOptions
  { startNode :: UUID
  , endNodes :: [UUID]
  } deriving (Eq, Ord, Show, Generic, FromJSON, ToJSON, Hashable)

-- | Messages from the server to the BinaryNinja Blaze plugin
data ServerToBinja = SBLogInfo { message :: Text }
                   | SBLogWarn { message :: Text }
                   | SBLogError { message :: Text }

                   | SBCfg { cfgId :: CfgId
                           -- So plugin can easily warn if it's out of date
                           , bndbHash :: BndbHash
                           , poiSearchResults :: Maybe PoiSearchResults
                           , pendingChanges :: Maybe PendingChanges
                           , groupOptions :: Maybe GroupOptions
                           -- TODO: send cfg with text
                           , cfg :: Cfg [[Token]]
                           }

                   | SBSnapshot { snapshotMsg :: Snapshot.ServerToBinja }

                   | SBPoi { poiMsg :: Poi.ServerToBinja }

                   | SBConstraint { constraintMsg :: C.ServerToBinja }

                   | SBNoop
                   deriving (Eq, Ord, Show, Generic, FromJSON, ToJSON, Hashable)

-- | Messages from the Binaryninja Blaze plugin to the server.
data BinjaToServer = BSConnect
                   | BSTextMessage { message :: Text }
                   | BSTypeCheckFunction { bndbHash :: BndbHash
                                         , address :: Word64
                                         }

                   | BSCfgNew
                     { bndbHash :: BndbHash
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

                   | BSGroupStart
                     { cfgId :: CfgId
                     , startNodeId :: UUID
                     }
                   | BSGroupDefine
                     { cfgId :: CfgId
                     , startNodeId :: UUID
                     , endNodeId :: UUID
                     }
                   | BSGroupExpand
                     { cfgId :: CfgId
                     , groupingNodeId :: UUID
                     }

                   | BSNoop

                   deriving (Eq, Ord, Show, Generic, FromJSON, ToJSON)

data FunctionDescriptor = FunctionDescriptor
  { name :: Text
  , address :: Int
  } deriving (Eq, Ord, Show, Generic)

instance ToJSON FunctionDescriptor
instance FromJSON FunctionDescriptor

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

newtype EventLoopError = EventLoopError Text
  deriving (Eq, Ord, Show, Generic)

newtype EventLoop a = EventLoop { _runEventLoop :: ReaderT SessionState (ExceptT EventLoopError IO) a }
  deriving newtype ( Functor
                   , Applicative
                   , Monad
                   , MonadReader SessionState
                   , MonadError EventLoopError
                   , MonadIO
                   , MonadThrow
                   , MonadCatch
                   , MonadMask
                   )

instance MonadDb EventLoop where
  withDb m = do
    conn <- view #dbConn <$> ask
    Db.runSelda conn m

runEventLoop :: EventLoop a -> SessionState -> IO (Either EventLoopError a)
runEventLoop m ctx = runExceptT . flip runReaderT ctx $ _runEventLoop m

forkEventLoop :: EventLoop () -> EventLoop ThreadId
forkEventLoop m = ask >>= \ctx -> liftIO . forkIO . void $ runEventLoop m ctx

forkEventLoop_ :: EventLoop () -> EventLoop ()
forkEventLoop_ = void . forkEventLoop

debug :: Text -> EventLoop ()
debug =  putText

type BinjaConns = HashMap ConnId WS.Connection

-- | Stores information needed for interaction with a single SessionId
-- This is cleaned and garbage-collected when all connections for this
-- SessionId are dropped.
data SessionState = SessionState
  { clientId :: ClientId
  , hostBinaryPath :: HostBinaryPath
  , binaryHash :: BinaryHash
  , binaryManager :: BinaryManager
  , cfgs :: TVar (HashMap CfgId (TVar (Cfg [Stmt])))
  , binjaConns :: TVar BinjaConns
  , eventHandlerThread :: TMVar ThreadId
  , eventHandlerWorkerThreads :: TVar (HashSet ThreadId)
  , eventInbox :: TQueue Event
  , dbConn :: Db.Conn
  , activePoi :: TVar (Maybe Poi)
  , callNodeRatingCtx :: CachedCalc BndbHash CallNodeRatingCtx
  } deriving (Generic)

addWorkerThread :: ThreadId -> SessionState -> STM ()
addWorkerThread tid ss
  = modifyTVar (ss ^. #eventHandlerWorkerThreads) $ HashSet.insert tid

removeCompletedWorkerThread :: ThreadId -> SessionState -> STM ()
removeCompletedWorkerThread tid ss
  = modifyTVar (ss ^. #eventHandlerWorkerThreads) $ HashSet.delete tid

emptySessionState
  :: ClientId
  -> HostBinaryPath
  -> BinaryHash
  -> BinaryManager
  -> Db.Conn
  -> CachedCalc BndbHash CallNodeRatingCtx
  -> STM SessionState
emptySessionState cid binPath binHash bm dbConn' ccCallRating
  = SessionState cid binPath binHash bm
    <$> newTVar HashMap.empty
    <*> newTVar HashMap.empty
    <*> newEmptyTMVar
    <*> newTVar HashSet.empty
    <*> newTQueue
    <*> pure dbConn'
    <*> newTVar Nothing
    <*> pure ccCallRating

-- | A `ConnId` is a unique websocket connection.
-- There is only one ConnId per BinaryNinja instance, shared across bndbs.
newtype ConnId = ConnId UUID
  deriving (Eq, Ord, Show, Generic)
  deriving newtype (Hashable, Random)

newConnId :: IO ConnId
newConnId = randomIO

-- | Stores active `SessionState`s and DB connection.
-- This is shared by both the websocket and web servers.
data AppState = AppState
  { serverConfig :: ServerConfig
  , binarySessions :: TVar (HashMap SessionId SessionState)
  , sessionConns :: TVar (HashMap ConnId (HashSet SessionId))
  , dbConn :: Db.Conn
  } deriving (Generic)

instance MonadDb (ReaderT AppState IO) where
  withDb m = do
    conn <- view #dbConn <$> ask
    Db.runSelda conn m

-- | Inserts a unique ConnId for a SessionId.
-- SessionIds can have multiple active connections if a single user opens multiple
-- copies of a BNDB.
addSessionConn :: SessionId -> ConnId -> AppState -> STM ()
addSessionConn sid cid st =
  readTVar tv >>= writeTVar tv . HashMap.alter upsert cid
  where
    upsert Nothing = Just $ HashSet.singleton sid
    upsert (Just s) = Just $ HashSet.insert sid s
    tv = st ^. #sessionConns

-- | Removes ConnId from the binja websocket conn map in SessionState.
-- Returns updated BinjaConns map
-- Mutatively sets the new map in the SessionState
cleanupBinjaConn :: ConnId -> SessionState -> STM BinjaConns
cleanupBinjaConn connId ss = do
  binjaConnsMap <- readTVar $ ss ^. #binjaConns
  case HashMap.member connId binjaConnsMap of
    False -> return binjaConnsMap
    True -> do
      let binjaConnsMap' = HashMap.delete connId binjaConnsMap
      writeTVar (ss ^. #binjaConns) binjaConnsMap'
      return binjaConnsMap'

-- | Removes ConnId from all sessions and frees up sessions with no active connections.
cleanupClosedConn :: ConnId -> AppState -> IO ()
cleanupClosedConn cid st = do
  threads <- atomically $ do
    sconns <- readTVar $ st ^. #sessionConns
    case HashMap.lookup cid sconns of
      Nothing -> return []
      Just sids -> do
        writeTVar (st ^. #sessionConns) $ HashMap.delete cid sconns
        binSessions <- readTVar $ st ^. #binarySessions
        concatMapM (cleanSession binSessions) . HashSet.toList $ sids
        where
          cleanSession :: HashMap SessionId SessionState -> SessionId -> STM [ThreadId]
          cleanSession binSessions sid =
            case HashMap.lookup sid binSessions of
              Nothing -> return []
              Just ss -> do
                binjaConnsMap <- cleanupBinjaConn cid ss
                case HashMap.null binjaConnsMap of
                  False -> return []
                  True -> do
                    mEventThread <- tryReadTMVar $ ss ^. #eventHandlerThread
                    writeTVar (st ^. #binarySessions) $ HashMap.delete sid binSessions
                    workers <- fmap HashSet.toList . readTVar
                      $ ss ^. #eventHandlerWorkerThreads
                    return $ maybeToList mEventThread <> workers
  mapM_ killThread threads
  putText $ "Killed " <> show (length threads) <> " thread(s)."

initAppState :: ServerConfig -> Db.Conn -> IO AppState
initAppState cfg' conn = AppState cfg'
  <$> newTVarIO HashMap.empty
  <*> newTVarIO HashMap.empty
  <*> pure conn

lookupSessionState :: SessionId -> AppState -> STM (Maybe SessionState)
lookupSessionState sid st = do
  m <- readTVar $ st ^. #binarySessions
  return $ HashMap.lookup sid m
