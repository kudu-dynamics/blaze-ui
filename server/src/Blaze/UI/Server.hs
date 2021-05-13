{- HLINT ignore "Use if" -}
{- HLINT ignore "Reduce duplication" -}

module Blaze.UI.Server where

import Blaze.UI.Prelude
import Blaze.Import.Source.BinaryNinja (BNImporter(BNImporter))
import qualified Blaze.Import.CallGraph
import qualified Data.Aeson as Aeson
import qualified Network.WebSockets as WS
import qualified Data.ByteString.Lazy as LBS
import qualified Data.ByteString.Char8 as BSC
-- import Control.Concurrent (threadDelay)
import Binja.Core (BNBinaryView)
import qualified Binja.Core as BN
import qualified Binja.Function as BNFunc
import Blaze.UI.Types hiding ( cfg, callNode )
import qualified Data.HashMap.Strict as HashMap
import qualified Blaze.Import.Source.BinaryNinja.CallGraph as CG
import qualified Blaze.Import.Source.BinaryNinja.Pil as Pil
import qualified Blaze.Import.Source.BinaryNinja.Cfg as BnCfg
import qualified Blaze.Types.Cfg as Cfg
import Blaze.Types.Cfg (Cfg)
import qualified Blaze.Cfg.Analysis as CfgA
import qualified Blaze.UI.Cfg as CfgUI
import qualified Data.Set as Set
import qualified Blaze.Graph as G
import Blaze.Types.Cfg.Interprocedural (InterCfg(InterCfg))
import qualified Blaze.Cfg.Interprocedural as ICfg
import Blaze.Pretty (prettyIndexedStmts, showHex)
import qualified Blaze.Types.Pil.Checker as Ch
import qualified Blaze.Pil.Checker as Ch
import qualified Blaze.UI.Web.Pil as WebPil
import Blaze.UI.Types.Cfg (convertPilCfg)
import qualified Blaze.UI.Types.Cfg.Snapshot as Snapshot
import Blaze.UI.Cfg.Snapshot as Snapshot
import Blaze.UI.Types.BinaryHash (getBinaryHash)
import qualified Blaze.UI.Db as Db
import Blaze.Types.Cfg (PilCfg)
import Blaze.UI.Types.Cfg (CfgId)
import Data.Time.Clock (getCurrentTime)
import Blaze.Pretty (pretty)


receiveJSON :: FromJSON a => WS.Connection -> IO (Either Text a)
receiveJSON conn = do
  x <- WS.receiveData conn :: IO LBS.ByteString
  return . first cs . Aeson.eitherDecode $ x

sendJSON :: ToJSON a => WS.Connection -> a -> IO ()
sendJSON conn x =
  WS.sendTextData conn (Aeson.encode x :: LBS.ByteString)


data SessionError
  = InvalidSessionId Text
  deriving (Eq, Ord, Show, Generic)

-- | returns session state or creates it.
-- bool indicates whether or not it was just now created
getSessionState :: SessionId
                -> AppState
                -> IO (Either SessionError (Bool, SessionState))
getSessionState sid st = atomically $ do
    m <- readTVar $ st ^. #binarySessions
    case HashMap.lookup sid m of
      Just ss -> return $ Right (False, ss)
      Nothing -> do
        case sessionIdToBinaryPath sid of
          Left e -> return . Left $ InvalidSessionId e
          Right binPath -> do
            ss <- emptySessionState binPath
            modifyTVar (st ^. #binarySessions) $ HashMap.insert sid ss
            return $ Right (True, ss)

removeSessionState :: SessionId -> AppState -> IO ()
removeSessionState sid st = atomically
  . modifyTVar (st ^. #binarySessions) $ HashMap.delete sid

createBinjaOutbox :: WS.Connection
                  -> SessionState
                  -> FilePath
                  -> IO ThreadId
createBinjaOutbox conn ss fp = do
  q <- newTQueueIO
  t <- forkIO . forever $ do
    msg <- atomically . readTQueue $ q
    sendJSON conn . BinjaMessage fp $ msg
  atomically . modifyTVar (ss ^. #binjaOutboxes)
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
  atomically . modifyTVar (ss ^. #webOutboxes)
    $ HashMap.insert t q
  return t

sendToBinja :: ServerToBinja -> EventLoop ()
sendToBinja msg = ask >>= \ctx -> liftIO . atomically $ do
  qs <- fmap HashMap.elems . readTVar $ ctx ^. #binjaOutboxes
  mapM_ (`writeTQueue` msg) qs

sendToWeb :: ServerToWeb -> EventLoop ()
sendToWeb msg = ask >>= \ctx -> liftIO . atomically $ do
  qs <- fmap HashMap.elems . readTVar $ ctx ^. #webOutboxes
  mapM_ (`writeTQueue` msg) qs

-- TODO: log warning to binja, web, and console
-- logWarn :: Text -> EventLoop ()
-- logWarn = 

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
      let fp = x ^. #bvFilePath
          sid = binaryPathToSessionId fp
          reply = sendJSON conn . BinjaMessage fp
          logInfo txt = do
            reply . SBLogInfo $ txt
            putText txt
      getSessionState sid st >>= \case
        Left serr -> putText $ "Session Error: " <> show serr
        Right (justCreated, ss) -> do
          let pushEvent = atomically . writeTQueue (ss ^. #eventInbox)
                          . BinjaEvent $ x ^. #action
          case justCreated of
            False -> do
              -- check to see if this conn has registered outbox thread
              case HashMap.member sid localOutboxThreads of
                False -> do
                  outboxThread <- createBinjaOutbox conn ss fp
                  pushEvent
                  logInfo $ "Blaze Connected. Attached to existing session for binary: " <> cs fp
                  logInfo "For web plugin, go here:"
                  logInfo $ webUri (st ^. #serverConfig) sid
                  binjaApp (HashMap.insert sid outboxThread localOutboxThreads) st conn
                True -> do
                  pushEvent >> binjaApp localOutboxThreads st conn

            True -> do
              logInfo $ "Connected. Loading binary: " <> cs fp
              ebv <- BN.getBinaryView fp
              case ebv of
                Left err -> do
                  reply . SBLogError $ "Blaze cannot open binary: " <> err -- 
                  putText $ "Cannot open binary: " <> err
                  atomically . modifyTVar (st ^. #binarySessions) $ HashMap.delete sid
              -- TODO: maybe send explicit disconnect?
                  return ()
                Right bv -> do
                  BN.updateAnalysisAndWait bv
                  logInfo $ "Loaded binary: " <> cs fp
                  logInfo "For web plugin, go here:"
                  logInfo $ webUri (st ^. #serverConfig) sid
                  atomically $ putTMVar (ss ^. #binaryView) bv
                  spawnEventHandler (cs fp) st ss
                  outboxThread <- createBinjaOutbox conn ss fp
                  pushEvent
                  binjaApp (HashMap.insert sid outboxThread localOutboxThreads) st conn

spawnEventHandler :: FilePath -> AppState -> SessionState -> IO ()
spawnEventHandler binPath st ss = do
  b <- atomically . isEmptyTMVar $ ss ^. #eventHandlerThread
  case b of
    False -> putText "Warning: spawnEventHandler -- event handler already spawned"
    True -> do
      binHash <- getBinaryHash binPath
      -- spawns event handler workers for new messages
      eventTid <- forkIO . forever $ do
        bv <- atomically . readTMVar $ ss ^. #binaryView
        msg <- atomically . readTQueue $ ss ^. #eventInbox
        let ctx = EventLoopCtx
                  binHash
                  binPath
                  bv
                  (ss ^. #binjaOutboxes)
                  (ss ^. #webOutboxes)
                  (ss ^. #cfgs)
                  (st ^. #serverConfig . #sqliteFilePath)

        -- TOOD: maybe should save these threadIds to kill later or limit?
        void . forkIO $ runEventLoop (mainEventLoop bv msg) ctx
      
      atomically $ putTMVar (ss ^. #eventHandlerThread) eventTid
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
  getSessionState sid st >>= \case
    Left serr -> putText $ "Session Error: " <> show serr
    Right (justCreated, ss) -> do
      case justCreated of
        True -> do
          let efp = sessionIdToBinaryPath sid
          case efp of
            Left err -> fatalError err
            Right fp -> do
              logInfo $ "Fresh Web client connected sans binja. Loading binary: " <> cs fp
              ebv <- BN.getBinaryView fp
              case ebv of
                Left err -> fatalError err
                Right bv -> do
                  BN.updateAnalysisAndWait bv
                  logInfo $ "Loaded binary: " <> cs fp
                  atomically $ putTMVar (ss ^. #binaryView) bv
                  spawnEventHandler (cs fp) st ss
        False -> return ()
      
      -- TODO: pass outboxThread in with event
      _outboxThread <- createWebOutbox conn ss

      forever $ do
        er <- receiveJSON conn :: IO (Either Text WebToServer)
        case er of
          Left err -> do
            putText $ "Error parsing JSON: " <> show err
          Right x -> do
            atomically . writeTQueue (ss ^. #eventInbox) . WebEvent $ x

  

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

-- saveNewCfg :: PilCfg -> EventLoop CfgId
-- saveNewCfg pcfg = do
--   cid <- Db.saveNewCfg pcfg
--   CfgUI.addCfg cid pcfg
--   return cid

setCfg :: CfgId -> PilCfg -> EventLoop ()
setCfg cid pcfg = do
  CfgUI.addCfg cid pcfg
  Db.setCfg cid pcfg

-- | Tries to getCfg from in-memory state. If that fails, try db.
-- if db has it, add it to cache
getCfg :: CfgId -> EventLoop (Maybe PilCfg)
getCfg cid = CfgUI.getCfg cid >>= \case
  Just pcfg -> return $ Just pcfg
  Nothing -> Db.getCfg cid >>= \case
    Nothing -> return Nothing
    Just pcfg -> do
      CfgUI.addCfg cid pcfg
      return $ Just pcfg

------------------------------------------
--- main event handler

mainEventLoop :: BNBinaryView -> Event -> EventLoop ()
mainEventLoop bv (WebEvent msg) = handleWebEvent bv msg
mainEventLoop bv (BinjaEvent msg) = handleBinjaEvent bv msg

handleWebEvent :: BNBinaryView -> WebToServer -> EventLoop ()
handleWebEvent bv = \case
  WSNoop -> debug "web noop"

  WSGetFunctionsList -> do
    funcs <- liftIO $ Blaze.Import.CallGraph.getFunctions bvi
    -- sendToWeb $ SWPilType WebPil.testPilType
    -- sendToWeb $ SWProblemType WebPil.testCallOp
    sendToWeb $ SWFunctionsList funcs
    
  WSTextMessage t -> do
    debug $ "Text Message from Web: " <> t
    sendToWeb $ SWTextMessage "I got your message and am flying with it!"
    sendToBinja . SBLogInfo $ "From the Web UI: " <> t

  WSGetTypeReport fn -> do
    debug $ "Generating type report for " <> show fn
    etr <- getFunctionTypeReport bv (fn ^. #address)
    case etr of
      Left err -> do
        let msg = "Failed to generate type report: " <> err
        debug msg
        sendToWeb . SWLogError $ msg

      Right (func, tr) -> do
        printTypeReportToConsole func tr
        let tr' = WebPil.toTypeReport tr
        -- let tr'' = tr' & #symStmts %~ (take 1 . drop 7)
        --let tr'' = tr' & #symStmts .~ WebPil.testCallOp
        liftIO $ pprint tr'
        sendToWeb $ SWFunctionTypeReport tr'
  where
    bvi = BNImporter bv

handleBinjaEvent :: BNBinaryView -> BinjaToServer -> EventLoop ()
handleBinjaEvent bv = \case
  BSConnect -> debug "Binja explicitly connected"  
  BSTextMessage t -> do
    debug $ "Message from binja: " <> t
    sendToBinja $ SBLogInfo "Got hello. Thanks."
    sendToBinja $ SBLogInfo "Working on finding an important integer..."
    sendToWeb $ SWTextMessage "Binja says hello"

    -- demo forking
    forkEventLoop_ $ do
      liftIO $ threadDelay 5000000 >> putText "calculating integer"
      n <- liftIO randomIO :: EventLoop Int
      sendToBinja . SBLogInfo
        $ "Here is your important integer: " <> show n
      
  BSTypeCheckFunction addr -> do
    etr <- getFunctionTypeReport bv (fromIntegral addr)
    case etr of
      Left err -> do
        let msg = "Failed to generate type report: " <> err
        debug msg
        sendToBinja . SBLogWarn $ msg

      Right (fn, tr) -> do
        printTypeReportToConsole fn tr
        sendToBinja . SBLogInfo $ "Completed checking " <> fn ^. BNFunc.name
        sendToBinja . SBLogInfo $ "See server log for results."

  -- Creates new CFG from function. Also create a new snapshot
  -- where the root node is the auto-cfg
  -- Sends back two messages: one auto-cfg, one new snapshot tree
  BSCfgNew funcAddr -> do
    mfunc <- liftIO $ CG.getFunction bv (fromIntegral funcAddr)
    case mfunc of
      Nothing -> sendToBinja
        . SBLogError $ "Couldn't find function at " <> showHex funcAddr
      Just func -> do
        mr <- liftIO $ BnCfg.getCfg (BNImporter bv) bv func
        case mr of
          Nothing -> sendToBinja
            . SBLogError $ "Error making CFG for function at " <> showHex funcAddr
          Just r -> do
            let pcfg = r ^. #result
            (bid, cid, snapBranch) <- Db.saveNewCfgAndBranch (func ^. #address) pcfg
            CfgUI.addCfg cid pcfg 
            -- TODO: this calls convertPilCfg and Snapshot.toTransport twice
            -- instead, do it once and pass converted cfg to db saving func
            sendToBinja . SBSnapshotMsg . Snapshot.SnapshotBranch bid
              $ Snapshot.toTransport snapBranch
            sendToBinja . SBCfg cid $ convertPilCfg pcfg
        debug "Created new branch and added auto-cfg."

  BSCfgExpandCall cfgId' callNode -> do
    debug $ "Binja expand call for:\n" <> cs (pshow callNode)
    mCfg <- getCfg cfgId'
    case mCfg of
      Nothing -> sendToBinja
        . SBLogError $ "Could not find existing CFG with id " <> show cfgId'
      Just cfg -> do
        case Cfg.getFullNodeMay cfg (Cfg.Call callNode) of
          Nothing ->
            sendToBinja . SBLogError $ "Could not find call node in Cfg"
          -- TODO: fix issue #160 so we can just send `CallNode ()` to expandCall
          Just (Cfg.Call fullCallNode) -> do
            let bs = ICfg.mkBuilderState (BNImporter bv)
            mCfg' <- liftIO . ICfg.build bs $ ICfg.expandCall (InterCfg cfg) fullCallNode

            case mCfg' of
              Left err ->
                -- TODO: more specific error
                sendToBinja . SBLogError . show $ err
              Right (InterCfg cfg') -> do
                let (InterCfg prunedCfg) = CfgA.prune $ InterCfg cfg'               
                -- pprint . Aeson.encode . convertPilCfg $ prunedCfg
                printPrunedStats cfg' prunedCfg
                sendToBinja . SBCfg cfgId' . convertPilCfg $ prunedCfg
                setCfg cfgId' prunedCfg
          Just _ -> do
            sendToBinja . SBLogError $ "Node must be a CallNode"
    
  BSCfgRemoveBranch cfgId' (node1, node2) -> do
    debug "Binja remove branch"
    mCfg <- getCfg cfgId'
    case mCfg of
      Nothing -> sendToBinja
        . SBLogError $ "Could not find existing CFG with id " <> show cfgId'
      Just cfg -> do
        case (,) <$> Cfg.getFullNodeMay cfg node1 <*> Cfg.getFullNodeMay cfg node2 of
          Nothing -> sendToBinja
            . SBLogError $ "Node(s) don't exist in Cfg"
          Just (fullNode1, fullNode2) -> do
            let cfg' = G.removeEdge (G.Edge fullNode1 fullNode2) cfg
                (InterCfg prunedCfg) = CfgA.prune $ InterCfg cfg'
            -- pprint . Aeson.encode . convertPilCfg $ prunedCfg
            printPrunedStats cfg' prunedCfg
            sendToBinja . SBCfg cfgId' . convertPilCfg $ prunedCfg
            setCfg cfgId' prunedCfg

  BSCfgRemoveNode cfgId' node' -> do
    debug "Binja remove node"
    mCfg <- getCfg cfgId'
    case mCfg of
      Nothing -> sendToBinja
        . SBLogError $ "Could not find existing CFG with id " <> show cfgId'
      Just cfg -> do
        case Cfg.getFullNodeMay cfg node' of
          Nothing -> sendToBinja
            . SBLogError $ "Node doesn't exist in Cfg"
          Just fullNode -> if fullNode == cfg ^. #root
            then sendToBinja $ SBLogError "Cannot remove root node"
            else do
              let cfg' = G.removeNode fullNode cfg
                  (InterCfg prunedCfg) = CfgA.prune $ InterCfg cfg'
              -- pprint . Aeson.encode . convertPilCfg $ prunedCfg
              printPrunedStats cfg' prunedCfg
              sendToBinja . SBCfg cfgId' . convertPilCfg $ prunedCfg
              setCfg cfgId' prunedCfg

  BSNoop -> debug "Binja noop"

  BSSnapshot snapMsg -> case snapMsg of
    _ -> undefined

    -- -- returns all branches for function
    -- BranchesOfFunction funcAddr -> undefined

    -- -- Loads cfg from snapshot tree
    -- -- 
    -- -- creates new cid for it
    -- -- returns new cfg and new snapshot tree with auto-cfg added
    -- Snapshot.Load cid -> undefined

    -- -- Saves auto-cfg cid as an immutable snapshot
    -- -- assumes cfg has already been loaded
    -- -- copies cfg to db with a different cid
    -- -- modifies snapshot tree
    -- -- sends back new snapshot tree
    -- Snapshot.Save cid mname -> undefined

    -- -- Renames previously saved immutable cfg
    -- Snapshot.Rename cid name -> undefined

printPrunedStats :: (Ord a, MonadIO m) => Cfg a -> Cfg a -> m ()
printPrunedStats a b = do
  putText "------------- Prune -----------"
  putText $ "Before: " <> show (Set.size $ G.nodes a) <> " nodes, "
    <> show (length $ G.edges a) <> " edges"
  putText $ "After: " <> show (Set.size $ G.nodes b) <> " nodes, "
    <> show (length $ G.edges b) <> " edges"


printTypeReportToConsole :: MonadIO m => BNFunc.Function -> Ch.TypeReport -> m ()
printTypeReportToConsole fn tr = do
  putText "\n------------------------Type Checking Function-------------------------"
  pprint fn
  putText ""
  pprint ("errors" :: Text, tr ^. #errors)
  putText ""
  prettyIndexedStmts $ tr ^. #symTypeStmts
  putText "-----------------------------------------------------------------------"

getFunctionTypeReport :: MonadIO m
                      => BNBinaryView
                      -> Address
                      -> m (Either Text (BNFunc.Function, Ch.TypeReport))
getFunctionTypeReport bv addr = liftIO $ do
  mFunc <- BNFunc.getFunctionStartingAt bv Nothing (fromIntegral addr)
  case mFunc of
    Nothing -> return . Left $ "Couldn't find function at: " <> show addr
    Just func -> do
      cgFunc <- CG.convertFunction bv func
      indexedStmts <- Pil.getFuncStatementsIndexed bv cgFunc
      let er = Ch.checkFunction indexedStmts
      return $ either (Left . show) (Right . (func,)) er

