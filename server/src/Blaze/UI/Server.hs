{- HLINT ignore "Use if" -}
{- HLINT ignore "Reduce duplication" -}

module Blaze.UI.Server where

import Blaze.UI.Prelude
import Blaze.Import.Source.BinaryNinja (BNImporter(BNImporter))
import qualified Data.Aeson as Aeson
import qualified Network.WebSockets as WS
import qualified Data.ByteString.Lazy as LBS
import qualified Data.ByteString.Char8 as BSC
import Binja.Core (BNBinaryView)
import qualified Binja.Function as BNFunc
import Blaze.UI.Types hiding ( cfg, callNode )
import qualified Data.HashMap.Strict as HashMap
import qualified Blaze.Import.Source.BinaryNinja.CallGraph as CG
import qualified Blaze.Import.Source.BinaryNinja.Pil as Pil
import qualified Blaze.Import.Source.BinaryNinja.Cfg as BnCfg
import qualified Blaze.Types.Cfg as Cfg
import Blaze.Types.Cfg (Cfg, PilCfg)
import qualified Blaze.Cfg.Analysis as CfgA
import qualified Blaze.UI.Cfg as CfgUI
import qualified Data.Set as Set
import qualified Blaze.Graph as G
import Blaze.Types.Cfg.Interprocedural (InterCfg(InterCfg))
import qualified Blaze.Cfg.Interprocedural as ICfg
import Blaze.Pretty (prettyIndexedStmts, showHex)
import qualified Blaze.Types.Pil.Checker as Ch
import qualified Blaze.Pil.Checker as Ch
import qualified Blaze.UI.Types.Cfg.Snapshot as Snapshot
import Blaze.UI.Types.Cfg.Snapshot (BranchId, Branch, BranchTree)
import qualified Blaze.UI.Cfg.Snapshot as Snapshot
import Blaze.UI.Types.BinaryHash (BinaryHash)
import qualified Blaze.UI.Db as Db
import Blaze.UI.Types.Cfg (CfgId, convertPilCfg)
import qualified Blaze.UI.BinaryManager as BM
import Blaze.UI.Types.HostBinaryPath (HostBinaryPath)
import Blaze.UI.Types.Session ( SessionId
                              , ClientId
                              , mkSessionId
                              )
import Data.Time.Clock (getCurrentTime)

receiveJSON :: FromJSON a => WS.Connection -> IO (Either Text a)
receiveJSON conn = do
  x <- WS.receiveData conn :: IO LBS.ByteString
  return . first cs . Aeson.eitherDecode $ x

sendJSON :: ToJSON a => WS.Connection -> a -> IO ()
sendJSON conn x =
  WS.sendTextData conn (Aeson.encode x :: LBS.ByteString)

data SessionError
  = InvalidSessionId Text
  | BinaryManagerError BM.BinaryManagerError
  deriving (Eq, Ord, Show, Generic)

-- | returns session state or creates it.
-- bool indicates whether or not it was just now created
getSessionState :: SessionId
                -> AppState
                -> IO (Bool, SessionState)
getSessionState sid st = atomically $ do
    m <- readTVar $ st ^. #binarySessions
    case HashMap.lookup sid m of
      Just ss -> return (False, ss)
      Nothing -> do
        bm <- BM.create
          (st ^. #serverConfig . #binaryManagerStorageDir)
          (sid ^. #clientId)
          (sid ^. #hostBinaryPath)
        ss <- emptySessionState (sid ^. #hostBinaryPath) bm
        modifyTVar (st ^. #binarySessions)
          $ HashMap.insert sid ss
        return (True, ss)

removeSessionState :: SessionId -> AppState -> IO ()
removeSessionState sid st = atomically
  . modifyTVar (st ^. #binarySessions) $ HashMap.delete sid

createBinjaOutbox :: WS.Connection
                  -> SessionState
                  -> ClientId
                  -> HostBinaryPath
                  -> IO ThreadId
createBinjaOutbox conn ss cid hpath = do
  q <- newTQueueIO
  t <- forkIO . forever $ do
    msg <- atomically . readTQueue $ q
    sendJSON conn . BinjaMessage cid hpath $ msg
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
      let cid = x ^. #clientId
          hpath = x ^. #hostBinaryPath
          sid = mkSessionId cid hpath
          reply = sendJSON conn . BinjaMessage cid hpath
          logInfo' txt = do
            reply . SBLogInfo $ txt
            putText txt
      (justCreated, ss) <- getSessionState sid st
      let pushEvent = atomically . writeTQueue (ss ^. #eventInbox)
                      . BinjaEvent
                      $ x ^. #action
      case justCreated of
        False -> do
          -- check to see if this conn has registered outbox thread
          case HashMap.member sid localOutboxThreads of
            False -> do
              outboxThread <- createBinjaOutbox conn ss cid hpath
              pushEvent
              logInfo' $ "Blaze Connected. Attached to existing session for binary: " <> show hpath
              -- logInfo "For web plugin, go here:"
              -- logInfo $ webUri (st ^. #serverConfig) sid
              binjaApp (HashMap.insert sid outboxThread localOutboxThreads) st conn
            True -> do
              pushEvent >> binjaApp localOutboxThreads st conn

        True -> do
          logInfo' "Connected:"
          spawnEventHandler cid st ss
          outboxThread <- createBinjaOutbox conn ss cid hpath
          pushEvent
          binjaApp (HashMap.insert sid outboxThread localOutboxThreads) st conn

spawnEventHandler :: ClientId -> AppState -> SessionState -> IO ()
spawnEventHandler cid st ss = do
  b <- atomically . isEmptyTMVar $ ss ^. #eventHandlerThread
  case b of
    False -> putText "Warning: spawnEventHandler -- event handler already spawned"
    True -> do
      -- spawns event handler workers for new messages
      eventTid <- forkIO . forever $ do
        msg <- atomically . readTQueue $ ss ^. #eventInbox
        let ctx = EventLoopCtx
                  cid
                  (ss ^. #binaryPath)
                  (ss ^. #binaryManager)
                  (ss ^. #binjaOutboxes)
                  (ss ^. #webOutboxes)
                  (ss ^. #cfgs)
                  (st ^. #serverConfig . #sqliteFilePath)

        -- TOOD: maybe should save these threadIds to kill later or limit?
        void . forkIO . void $ runEventLoop (mainEventLoop msg) ctx
      
      atomically $ putTMVar (ss ^. #eventHandlerThread) eventTid
      putText "Spawned event handlers"

webApp :: AppState -> SessionId -> WS.Connection -> IO ()
webApp _st _sid _conn = do
  return ()

app :: AppState -> WS.PendingConnection -> IO ()
app st pconn = case splitPath of
  ["binja"] -> WS.acceptRequest pconn >>= binjaApp HashMap.empty st
  _ -> do
    putText $ "Rejected request to invalid path: " <> cs path
    WS.rejectRequest pconn $ "Invalid path: " <> path
  where
    path = WS.requestPath $ WS.pendingRequest pconn
    splitPath = drop 1 . BSC.splitWith (== '/') $ path

run :: ServerConfig -> IO ()
run cfg = do
  st <- initAppState cfg
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

setCfg :: CfgId -> PilCfg -> EventLoop ()
setCfg cid pcfg = do
  CfgUI.addCfg cid pcfg
  Db.setCfg cid pcfg

-- | Tries to getCfg from in-memory state. If that fails, try db.
-- if db has it, add it to cache
getCfg :: CfgId -> EventLoop PilCfg
getCfg cid = CfgUI.getCfg cid >>= \case
  Just pcfg -> return pcfg
  Nothing -> Db.getCfg cid >>= \case
    Nothing -> throwError . EventLoopError $ "Could not find existing CFG with id " <> show cid
    Just pcfg -> do
      CfgUI.addCfg cid pcfg
      return pcfg

sendLatestSnapshots :: EventLoop ()
sendLatestSnapshots = do
  ctx <- ask
  branches <- HashMap.toList <$> Db.getAllBranchesForClient (ctx ^. #clientId) :: EventLoop [(HostBinaryPath, [(BranchId, Snapshot.Branch Snapshot.BranchTree)])]
  sendToBinja
    . SBSnapshot
    . Snapshot.BranchesOfClient
    . fmap (over _2 (fmap (over _2 Snapshot.toTransport)))
    $ branches

------------------------------------------
--- main event handler

-- | log error sends error to binja, prints to server log, and halts eventloop
-- (maybe should be named something more than "log...")
logError :: Text -> EventLoop a
logError errMsg = do
  sendToBinja . SBLogError $ errMsg
  putText $ "ERROR: " <> errMsg
  throwError $ EventLoopError errMsg

logWarn :: Text -> EventLoop ()
logWarn warnMsg = do
  sendToBinja . SBLogWarn $ warnMsg
  putText $ "WARNING: " <> warnMsg

logInfo :: Text -> EventLoop ()
logInfo infoMsg = do
  sendToBinja . SBLogInfo $ infoMsg
  putText infoMsg

getCfgBinaryView :: CfgId -> EventLoop (BNBinaryView, BinaryHash)
getCfgBinaryView cid = Db.getCfgBinaryHash cid >>= \case
  Nothing ->
    logError $ "Could not find binary hash version for cfg: " <> show cid
    
  Just h -> do
    bm <- view #binaryManager <$> ask
    BM.loadBndb bm h >>= either (logError . show) (return . (,h))

getCfgBinaryHash :: CfgId -> EventLoop BinaryHash
getCfgBinaryHash cid = Db.getCfgBinaryHash cid >>= \case
  Nothing -> throwError . EventLoopError $ "getCfgBinaryHash cannot find CfgId: " <> show cid
  Just h -> return h

getBinaryView :: BinaryHash -> EventLoop BNBinaryView
getBinaryView bhash = do
  bm <- view #binaryManager <$> ask
  BM.loadBndb bm bhash >>= either (logError . show) return

getBranch :: BranchId
          -> EventLoop (Branch BranchTree)
getBranch bid = Db.getBranch bid >>= \case
  Nothing -> logError $ "Could not find snapshot branch: " <> show bid
  Just b -> return b

getBranchId :: CfgId -> EventLoop BranchId
getBranchId cid = Db.getCfgBranchId cid >>= \case
  Nothing -> logError $ "Could not find branch id for: " <> show cid
  Just bid -> return bid

mainEventLoop :: Event -> EventLoop ()
mainEventLoop (WebEvent msg) = handleWebEvent msg
mainEventLoop (BinjaEvent msg) = handleBinjaEvent msg

handleWebEvent :: WebToServer -> EventLoop ()
handleWebEvent _msg =
  debug "Web events currently not handled"

handleBinjaEvent :: BinjaToServer -> EventLoop ()
handleBinjaEvent = \case
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
      
  BSTypeCheckFunction bhash addr -> do
    bv <- getBinaryView bhash
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
  BSCfgNew bhash funcAddr -> do
    bv <- getBinaryView bhash
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
            ctx <- ask
            let pcfg = r ^. #result
            (_bid, cid, _snapBranch) <- Db.saveNewCfgAndBranch
              (ctx ^. #clientId)
              (ctx ^. #hostBinaryPath)
              bhash
              (func ^. #address)
              pcfg
            CfgUI.addCfg cid pcfg 
            sendLatestSnapshots
            sendToBinja . SBCfg cid bhash $ convertPilCfg pcfg
        debug "Created new branch and added auto-cfg."

  BSCfgExpandCall cfgId' callNode -> do
    (bv, bhash) <- getCfgBinaryView cfgId'
    debug $ "Binja expand call for:\n" <> cs (pshow callNode)
    cfg <- getCfg cfgId'
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
            sendToBinja . SBCfg cfgId' bhash . convertPilCfg $ prunedCfg
            setCfg cfgId' prunedCfg
      Just _ -> do
        sendToBinja . SBLogError $ "Node must be a CallNode"
    
  BSCfgRemoveBranch cfgId' (node1, node2) -> do
    debug "Binja remove branch"
    -- TODO: just get the bhash since bv isn't used
    bhash <- getCfgBinaryHash cfgId'
    cfg <- getCfg cfgId'
    case (,) <$> Cfg.getFullNodeMay cfg node1 <*> Cfg.getFullNodeMay cfg node2 of
      Nothing -> sendToBinja
        . SBLogError $ "Node or nodes don't exist in Cfg"
      Just (fullNode1, fullNode2) -> do
        let cfg' = G.removeEdge (G.Edge fullNode1 fullNode2) cfg
            (InterCfg prunedCfg) = CfgA.prune $ InterCfg cfg'
        -- pprint . Aeson.encode . convertPilCfg $ prunedCfg
        printPrunedStats cfg' prunedCfg
        sendToBinja . SBCfg cfgId' bhash . convertPilCfg $ prunedCfg
        setCfg cfgId' prunedCfg

  BSCfgRemoveNode cfgId' node' -> do
    debug "Binja remove node"
    -- TODO: just get the bhash since bv isn't used
    bhash <- getCfgBinaryHash cfgId'
    cfg <- getCfg cfgId'
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
          sendToBinja . SBCfg cfgId' bhash . convertPilCfg $ prunedCfg
          setCfg cfgId' prunedCfg

  BSNoop -> debug "Binja noop"

  BSSnapshot snapMsg -> case snapMsg of
    Snapshot.GetAllBranchesOfClient -> sendLatestSnapshots
      
    Snapshot.GetAllBranchesOfBinary -> do
      ctx <- ask
      let hpath = ctx ^. #hostBinaryPath
      branches <- Db.getAllBranchesForBinary (ctx ^. #clientId) hpath
      sendToBinja
        . SBSnapshot
        . Snapshot.BranchesOfBinary hpath
        . fmap (over _2 Snapshot.toTransport)
        $ branches
      
    -- returns all branches for function
    Snapshot.GetBranchesOfFunction funcAddr -> do
      ctx <- ask
      branches <- Db.getBranchesForFunction
                  (ctx ^. #clientId)
                  (ctx ^. #hostBinaryPath)
                  (fromIntegral funcAddr)
      sendToBinja
        . SBSnapshot
        . Snapshot.BranchesOfFunction funcAddr
        . fmap (over _2 Snapshot.toTransport)
        $ branches  

    Snapshot.RenameBranch bid name' -> do
      Db.setBranchName bid (Just name')
      Db.getBranch bid >>= \case
        Nothing -> logError $ "Could not find snapshot with id: " <> show bid
        Just _br -> sendLatestSnapshots

    -- load directly if autosave, otherwise create autosave branch
    Snapshot.LoadSnapshot bid cid -> do
      b <- getBranch bid
      (newCid, cfg') <- case Snapshot.isAutosave cid (b ^. #tree) of
        Nothing -> logError $ "Could not find snapshot info for: " <> show cid
        Just True -> (cid,) <$> getCfg cid
        Just False -> do
          cfg' <- getCfg cid
          newAutoCid <- liftIO randomIO
          Db.saveNewCfg_ bid newAutoCid cfg'

          -- TODO: is this necessary? should already be up to date
          Db.setCfg cid cfg'

          -- change CfgId in cache to new auto-saved cfg
          CfgUI.changeCfgId cid newAutoCid
          utc <- liftIO getCurrentTime
          let updatedTree = Snapshot.immortalizeAutosave cid newAutoCid utc $ b ^. #tree
          Db.setBranchTree bid updatedTree

          sendLatestSnapshots
          return (newAutoCid, cfg')
      sendToBinja . SBCfg newCid (b ^. #bndbHash) . convertPilCfg $ cfg'

        
    Snapshot.SaveSnapshot cid -> do
      -- Already exists and this point:
      --     * branch containing cid
      --     * cid is in branch, saved as an autocfg
      -- get cfg from sessionstate
      -- DB: save old cid as immutables cfg
      --     change cid in sessionstate to newly created autoCid
      --     change cid attr to be immutable in snap branch tree
      --     add autoCid as child of cid in snap branch tree
      --     send back new autoCid cfg and updated branch
      cfg <- getCfg cid
      newAutoCid <- liftIO randomIO

      bid <- getBranchId cid
      
      -- TODO: these convert same PilCfg to transport-cfg twice...
      Db.saveNewCfg_ bid newAutoCid cfg

      -- TODO: is this necessary? should already be up to date
      Db.setCfg cid cfg

      -- change CfgId in cache to new auto-saved cfg
      CfgUI.changeCfgId cid newAutoCid

      b <- getBranch bid

      utc <- liftIO getCurrentTime
      let updatedTree = Snapshot.immortalizeAutosave cid newAutoCid utc $ b ^. #tree
      Db.setBranchTree bid updatedTree

      logInfo $ "Saved iCfg: " <> show cid

      sendLatestSnapshots
      -- sendToBinja . SBSnapshot . Snapshot.SnapshotBranch bid
      --   $ Snapshot.toTransport updatedBranch

    -- -- Renames previously saved immutable cfg
    Snapshot.RenameSnapshot cid name' -> do
      bid <- getBranchId cid
      Db.setCfgName bid cid name'

printPrunedStats :: (Ord a, MonadIO m) => Cfg a -> Cfg a -> m ()
printPrunedStats a b = do
  putText "------------- Prune -----------"
  putText $ "Before: " <> show (Set.size $ G.nodes a) <> " nodes, "
    <> show (length $ G.edges a) <> " edges"
  putText $ "After: " <> show (Set.size $ G.nodes b) <> " nodes, "
    <> show (length $ G.edges b) <> " edges"


printTypeReportToConsole :: MonadIO m => BNFunc.Function -> Ch.TypeReport -> m ()
printTypeReportToConsole fn tr = liftIO $ do
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

