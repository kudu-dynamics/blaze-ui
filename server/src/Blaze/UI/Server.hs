{- HLINT ignore "Use if" -}

module Blaze.UI.Server where

import Blaze.UI.Prelude
import qualified Data.Aeson as Aeson
import qualified Network.WebSockets as WS
import qualified Data.ByteString.Lazy as LBS
import qualified Data.ByteString.Char8 as BSC
-- import Control.Concurrent (threadDelay)
import Binja.Core (BNBinaryView)
import qualified Binja.Core as BN
import qualified Binja.Function as BNFunc
import Blaze.UI.Types
import qualified Data.HashMap.Strict as HashMap
import Blaze.Pretty (prettyIndexedStmts)
import qualified Blaze.Types.Pil.Checker as Ch
import qualified Blaze.Pil.Checker as Ch


receiveJSON :: FromJSON a => WS.Connection -> IO (Either Text a)
receiveJSON conn = do
  x <- WS.receiveData conn :: IO LBS.ByteString
  return . first cs . Aeson.eitherDecode $ x

sendJSON :: ToJSON a => WS.Connection -> a -> IO ()
sendJSON conn x =
  WS.sendTextData conn (Aeson.encode x :: LBS.ByteString)


-- | returns session state or creates it.
-- bool indicates whether or not it was just now created
getSessionState :: Maybe Text -> SessionId -> AppState ->  IO (Bool, SessionState)
getSessionState binPath sid st = do
  atomically $ do
    m <- readTVar $ st ^. binarySessions
    case HashMap.lookup sid m of
      Just ss -> return (False, ss)
      Nothing -> do
        ss <- emptySessionState binPath
        modifyTVar (st ^. binarySessions) $ HashMap.insert sid ss
        return (True, ss)

removeSessionState :: SessionId -> AppState -> IO ()
removeSessionState sid st = atomically
  . modifyTVar (st ^. binarySessions) $ HashMap.delete sid

createBinjaOutbox :: WS.Connection
             -> SessionState
             -> Text
             -> IO ThreadId
createBinjaOutbox conn ss fp = do
  q <- newTQueueIO
  t <- forkIO . forever $ do
    msg <- atomically . readTQueue $ q
    sendJSON conn . BinjaMessage fp $ msg
  atomically . modifyTVar (ss ^. binjaOutboxes)
    $ HashMap.insert t q
  return t

createWebOutbox :: WS.Connection
                -> SessionState
                -> IO ThreadId
createWebOutbox conn ss = do
  q <- newTQueueIO
  t <- forkIO . forever $ do
    msg <- atomically . readTQueue $ q
    sendJSON conn msg
  atomically . modifyTVar (ss ^. webOutboxes)
    $ HashMap.insert t q
  return t

-- | Websocket message handler for binja.
-- This handles messages for multiple binaries to/from single binja.
-- localOutboxThreads is needed to store if an outbox thread has already been
-- started for this particular binja conn, since there might already be an outbox
-- to a different binja.
binjaApp :: HashMap SessionId ThreadId -> AppState -> WS.Connection -> IO ()
binjaApp localOutboxThreads st conn = do
  er <- receiveJSON conn :: IO (Either Text (BinjaMessage BinjaToServer))
  -- putText $ "got binja message: " <> show er
  case er of
    Left err -> do
      putText $ "Error parsing JSON: " <> show err
    Right x -> do
      let fp = x ^. bvFilePath
          sid = binaryPathToSessionId fp
          reply = sendJSON conn . BinjaMessage fp
          logInfo txt = do
            reply . SBLogInfo $ txt
            putText txt
      (justCreated, ss) <- getSessionState (Just fp) sid st
      let pushEvent = atomically . writeTQueue (ss ^. eventInbox)
                      . BinjaEvent $ x ^. action
      case justCreated of
        False -> do
          -- check to see if this conn has registered outbox thread
          case HashMap.member sid localOutboxThreads of
            False -> do
              outboxThread <- createBinjaOutbox conn ss fp
              pushEvent
              logInfo $ "Blaze Connected. Attached to existing session for binary: " <> fp
              logInfo "For web plugin, go here:"
              logInfo $ webUri (st ^. serverConfig) sid
              binjaApp (HashMap.insert sid outboxThread localOutboxThreads) st conn
            True -> do
              pushEvent >> binjaApp localOutboxThreads st conn

        True -> do
          logInfo $ "Connected. Loading binary: " <> fp
          ebv <- BN.getBinaryView . cs $ fp
          case ebv of
            Left err -> do
              reply . SBLogError $ "Blaze cannot open binary: " <> err -- 
              putText $ "Cannot open binary: " <> err
              atomically . modifyTVar (st ^. binarySessions) $ HashMap.delete sid
              -- TODO: maybe send explicit disconnect?
              return ()
            Right bv -> do
              BN.updateAnalysisAndWait bv
              logInfo $ "Loaded binary: " <> fp
              logInfo "For web plugin, go here:"
              logInfo $ webUri (st ^. serverConfig) sid
              atomically $ putTMVar (ss ^. binaryView) bv
              spawnEventHandler ss
              outboxThread <- createBinjaOutbox conn ss fp
              pushEvent
              binjaApp (HashMap.insert sid outboxThread localOutboxThreads) st conn

spawnEventHandler :: SessionState -> IO ()
spawnEventHandler ss = do
  b <- atomically $ do
    b1 <- isEmptyTMVar $ ss ^. eventHandlerThread
    b2 <- isEmptyTMVar $ ss ^. blazeActionHandlerThread
    return $ b1 || b2
  case b of
    False -> putText "Warning: spawnEventHandler -- event handler already spawned"
    True -> do
      eventTid <- forkIO . forever $ do
        bv <- atomically . readTMVar $ ss ^. binaryView
        msg <- atomically . readTQueue $ ss ^. eventInbox
        (_, s) <- runEventLoop (mainEventLoop bv msg) $ EventLoopState [] [] []
        atomically $ do
          binjas <- fmap HashMap.elems . readTVar $ ss ^. binjaOutboxes
          webs <- fmap HashMap.elems . readTVar $ ss ^. webOutboxes

          -- TODO: change these to Seq so we don't have to do reverse
          mapM_ (flip writeManyTQueue . reverse $ s ^. binjaOutput) binjas
          mapM_ (flip writeManyTQueue . reverse $ s ^. webOutput) webs
          writeManyTQueue (ss ^. blazeActions) . reverse $ s ^. blazeActions
      
      blazeActionTid <- forkIO . forever $ do
        ioAction <- atomically . readTQueue $ ss ^. blazeActions
        void . forkIO $ do
          r <- ioAction
          atomically . writeTQueue (ss ^. eventInbox) $ BlazeEvent r

      atomically $ putTMVar (ss ^. eventHandlerThread) eventTid
      atomically $ putTMVar (ss ^. blazeActionHandlerThread) blazeActionTid
      putText "Spawned event handlers"

webUri :: ServerConfig -> SessionId -> Text
webUri cfg (SessionId sid) = "http://"
  <> serverHost cfg
  <> ":" <> show (serverHttpPort cfg)
  <> "/" <> cs sid

webApp :: AppState -> SessionId -> WS.Connection -> IO ()
webApp st sid conn = do
  let fatalError t = do
        sendJSON conn . SWLogError $ t
        removeSessionState sid st
        WS.sendClose conn t
      logInfo = sendJSON conn . SWLogInfo
  (justCreated, ss) <- getSessionState Nothing sid st
  case justCreated of
    True -> do
      let efp = sessionIdToBinaryPath sid
      case efp of
        Left err -> fatalError err
        Right fp -> do
          logInfo $ "Fresh Web client connected sans binja. Loading binary: " <> fp
          ebv <- BN.getBinaryView . cs $ fp
          case ebv of
            Left err -> fatalError err
            Right bv -> do
              BN.updateAnalysisAndWait bv
              logInfo $ "Loaded binary: " <> fp
              atomically $ putTMVar (ss ^. binaryView) bv
              spawnEventHandler ss
    False -> return ()
      
  -- TODO: pass outboxThread in with event
  _outboxThread <- createWebOutbox conn ss

  forever $ do
    er <- receiveJSON conn :: IO (Either Text WebToServer)
    case er of
      Left err -> do
        putText $ "Error parsing JSON: " <> show err
      Right x -> do
        atomically . writeTQueue (ss ^. eventInbox) . WebEvent $ x

  

app :: AppState -> WS.PendingConnection -> IO ()
app st pconn = case splitPath of
  ["binja"] -> WS.acceptRequest pconn >>= binjaApp HashMap.empty st
  ["web", sid] -> WS.acceptRequest pconn >>= webApp st (SessionId $ cs sid)
  _ -> do
    putText $ "Rejected request to invalid path: " <> cs path
    WS.rejectRequest pconn $ "Invalid path: " <> path
  where
    path = WS.requestPath $ WS.pendingRequest pconn
    splitPath = drop 1 . BSC.splitWith (== '/') $ path

run :: ServerConfig -> IO ()
run cfg = do
  st <- emptyAppState cfg
  putText $ "Starting Blaze UI Server at "
    <> serverHost cfg
    <> ":"
    <> show (serverWsPort cfg)
  WS.runServer (cs $ serverHost cfg) (serverWsPort cfg) (app st)


testClient :: BinjaMessage BinjaToServer -> WS.Connection -> IO (BinjaMessage ServerToBinja)
testClient msg conn = do
  sendJSON conn msg
  (Right r) <- receiveJSON conn
  return r

runClient :: ServerConfig -> (WS.Connection -> IO a) -> IO a
runClient cfg = WS.runClient (cs $ serverHost cfg) (serverWsPort cfg) ""


------------------------------------------
--- main event handler

mainEventLoop :: BNBinaryView -> Event -> EventLoop ()
mainEventLoop bv (WebEvent msg) = handleWebEvent bv msg
mainEventLoop bv (BinjaEvent msg) = handleBinjaEvent bv msg
mainEventLoop bv (BlazeEvent msg) = handleBlazeEvent bv msg

handleWebEvent :: BNBinaryView -> WebToServer -> EventLoop ()
handleWebEvent _bv = \case
  WSNoop -> debug "web noop"
  WSTextMessage t -> do
    debug $ "Text Message from Web: " <> t
    sendToWeb $ SWTextMessage "I got your message and am flying with it!"
    sendToBinja . SBLogInfo $ "From the Web UI: " <> t


handleBinjaEvent :: BNBinaryView -> BinjaToServer -> EventLoop ()
handleBinjaEvent bv = \case
  BSConnect -> debug "Binja explicitly connected"  
  BSTextMessage t -> do
    debug $ "Message from binja: " <> t
    sendToBinja $ SBLogInfo "Got hello. Thanks."
    sendToBinja $ SBLogInfo "Working on finding an important integer..."
    sendToWeb $ SWTextMessage "Binja says hello"
    doAction . fmap BZImportantInteger
      $ threadDelay 5000000 >> putText "calculating integer" >> randomIO
    doAction $ threadDelay 10000000 >> putText "Delayed noop event (10s)" >> return BZNoop
  BSTypeCheckFunction addr -> do
    doAction $ do
      mFunc <- BNFunc.getFunctionStartingAt bv Nothing (fromIntegral addr)
      case mFunc of
        Nothing -> return BZNoop
        Just func -> do
          er <- Ch.checkFunction func
          case er of
            Left err -> pprint err >> return BZNoop
            Right tr -> return $ BZTypeCheckFunctionReport func tr
  BSNoop -> debug "Binja noop"


handleBlazeEvent :: BNBinaryView -> BlazeToServer -> EventLoop ()
handleBlazeEvent _bv = \case
  BZNoop -> debug "Blaze noop"
  BZTypeCheckFunctionReport fn r -> do
    nonAsyncIO $ do
      putText "\n------------------------Type Checking Function-------------------------"
      pprint fn
      putText ""
      pprint ("errors" :: Text, r ^. Ch.errors)
      putText ""
      prettyIndexedStmts $ r ^. Ch.symTypeStmts
      putText "-----------------------------------------------------------------------"
    sendToBinja . SBLogInfo $ "Completed checking " <> fn ^. BNFunc.name
    sendToBinja . SBLogInfo $ "See server log for results."
  BZImportantInteger n -> sendToBinja . SBLogInfo
    $ "Here is your important integer: " <> show n


