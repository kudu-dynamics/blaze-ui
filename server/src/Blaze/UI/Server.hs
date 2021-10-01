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
import Blaze.UI.Types hiding ( cfg, callNode, stmtIndex )
import qualified Data.HashMap.Strict as HashMap
import qualified Blaze.Import.Source.BinaryNinja.CallGraph as CG
import qualified Blaze.Import.Source.BinaryNinja.Pil as Pil
import qualified Blaze.Import.Source.BinaryNinja.Cfg as BnCfg
import qualified Blaze.Types.Cfg as Cfg
import Blaze.Types.Cfg (Cfg, PilCfg, CfNode)
import qualified Blaze.Cfg.Analysis as CfgA
import qualified Blaze.UI.Cfg as CfgUI
import qualified Data.HashSet as HashSet
import qualified Blaze.Graph as G
import Blaze.Types.Cfg.Interprocedural (InterCfg(InterCfg, unInterCfg))
import qualified Blaze.Cfg.Interprocedural as ICfg
import Blaze.Pretty (prettyIndexedStmts, showHex)
import qualified Blaze.Types.Pil.Checker as Ch
import qualified Blaze.Pil.Checker as Ch
import qualified Blaze.UI.Types.Constraint as C
import qualified Blaze.UI.Types.Cfg.Snapshot as Snapshot
import Blaze.UI.Types.Cfg.Snapshot (BranchId, Branch, BranchTree, SnapshotType)
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
import Blaze.Function (Function)
import qualified Blaze.UI.Db.Poi as PoiDb
import qualified Blaze.UI.Types.Poi as Poi
import Blaze.Types.Cfg.Analysis (Target(Target))
import qualified Blaze.UI.Types.CachedCalc as CC
import qualified Blaze.Pil.Parse as Parse
import qualified Blaze.Types.Pil as Pil
import qualified Blaze.Cfg.Solver.General as GSolver

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
getSessionState :: SessionId
                -> AppState
                -> IO SessionState
getSessionState sid st = do
  (ss, justCreated) <- atomically $ do
    m <- readTVar $ st ^. #binarySessions
    case HashMap.lookup sid m of
      Just ss -> return (ss, False)
      Nothing -> do
        bm <- BM.create
          (st ^. #serverConfig . #binaryManagerStorageDir)
          (sid ^. #clientId)
          (sid ^. #hostBinaryPath)
        ccCallNodeRating <- CC.create
        ss <- emptySessionState (sid ^. #hostBinaryPath) bm (st ^. #dbConn) ccCallNodeRating
        modifyTVar (st ^. #binarySessions)
          $ HashMap.insert sid ss
        return (ss, True)
  when justCreated $ spawnEventHandler (sid ^. #clientId) st ss
  return ss

removeSessionState :: SessionId -> AppState -> IO ()
removeSessionState sid st = atomically $ do
  modifyTVar (st ^. #binarySessions) $ HashMap.delete sid

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

sendToBinja :: ServerToBinja -> EventLoop ()
sendToBinja msg = ask >>= \ctx -> liftIO . atomically $ do
  qs <- fmap HashMap.elems . readTVar $ ctx ^. #binjaOutboxes
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
      ss <- getSessionState sid st
      let pushEvent = atomically . writeTQueue (ss ^. #eventInbox)
                      . BinjaEvent
                      $ x ^. #action
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
                  (ss ^. #cfgs)
                  (st ^. #dbConn)
                  (ss ^. #activePoi)
                  (ss ^. #callNodeRatingCtx)

        -- TOOD: maybe should save these threadIds to kill later or limit?
        void . forkIO . void $ runEventLoop (mainEventLoop msg) ctx

      atomically $ putTMVar (ss ^. #eventHandlerThread) eventTid
      putText "Spawned event handlers"

app :: AppState -> WS.PendingConnection -> IO ()
app st pconn = case splitPath of
  ["binja"] -> WS.acceptRequest pconn >>= binjaApp HashMap.empty st
  _ -> do
    putText $ "Rejected request to invalid path: " <> cs path
    WS.rejectRequest pconn $ "Invalid path: " <> path
  where
    path = WS.requestPath $ WS.pendingRequest pconn
    splitPath = drop 1 . BSC.splitWith (== '/') $ path

run :: AppState -> IO ()
run st = do
  putText $ "Starting Blaze UI Server at "
    <> serverHost cfg
    <> ":"
    <> show (serverWsPort cfg)
  WS.runServer (cs $ serverHost cfg) (serverWsPort cfg) (app st)
  where
    cfg = st ^. #serverConfig

testClient :: BinjaMessage BinjaToServer -> WS.Connection -> IO (BinjaMessage ServerToBinja)
testClient msg conn = do
  sendJSON conn msg
  (Right r) <- receiveJSON conn
  return r

runClient :: ServerConfig -> (WS.Connection -> IO a) -> IO a
runClient cfg = WS.runClient (cs $ serverHost cfg) (serverWsPort cfg) ""

getCfgType :: CfgId -> EventLoop SnapshotType
getCfgType cid = Db.getCfgType cid >>= \case
  Nothing -> throwError . EventLoopError $ "Could not find existing CFG with id " <> show cid
  Just t -> return t

-- | Saves modified cfg. If CfgId is immutable, it creates autosave
-- and returns Just new autosave id.
-- If already autosave, it just saves and returns Nothing
autosaveCfg :: CfgId -> PilCfg -> EventLoop (Maybe CfgId)
autosaveCfg cid pcfg = getCfgType cid >>= \case
  Snapshot.Autosave -> do
    setCfg cid pcfg
    return Nothing
  Snapshot.Immutable -> do
    autoCid <- liftIO randomIO
    bid <- getBranchId cid
    Db.modifyBranchTree bid $ Snapshot.addChild cid autoCid
    CfgUI.addCfg autoCid pcfg
    Db.saveNewCfg_ bid autoCid pcfg Snapshot.Autosave
    return $ Just autoCid

sendCfgWithCallRatings :: BinaryHash -> PilCfg -> CfgId -> EventLoop ()
sendCfgWithCallRatings bhash cfg cid = do
  poiSearch <- getPoiSearchResults bhash cfg
  sendToBinja . SBCfg cid bhash poiSearch Nothing . convertPilCfg $ cfg

refreshActiveCfg :: CfgId -> EventLoop ()
refreshActiveCfg cid = do
  (_, bhash) <- getCfgBinaryView cid
  cfg <- getCfg cid
  sendCfgWithCallRatings bhash cfg cid

-- | Used after `autosaveCfg`. If second CfgId is Nothing, just send first.
-- If second is Just, send new CfgId. In both cases, send new snapshot tree.
sendCfgAndSnapshots :: BinaryHash -> PilCfg -> CfgId -> Maybe CfgId -> EventLoop ()
sendCfgAndSnapshots bhash pcfg cid newCid = do
  sendCfgWithCallRatings bhash pcfg $ fromMaybe cid newCid
  sendLatestClientSnapshots

sendDiffCfg :: BinaryHash -> CfgId -> PilCfg -> PilCfg -> EventLoop ()
sendDiffCfg bhash cid old new = do
  CfgUI.addCfg cid new
  if isEmptyChanges changes then
    autosaveCfg cid new >>= sendCfgAndSnapshots bhash new cid
  else
    sendToBinja $ SBCfg cid bhash Nothing (Just changes) $ convertPilCfg old

  where
    isEmptyChanges (PendingChanges [] []) = True
    isEmptyChanges _ = False
    changes = PendingChanges removedNodes' removedEdges'
    removedNodes' = fmap Cfg.getNodeUUID
                    . HashSet.toList
                    $ CfgUI.getRemovedNodes old new
    removedEdges' = fmap CfgUI.edgeToUUIDTuple
                    . HashSet.toList
                    $ CfgUI.getRemovedEdges old new

setCfg :: CfgId -> PilCfg -> EventLoop ()
setCfg cid pcfg = do
  CfgUI.addCfg cid pcfg
  Db.setCfg cid pcfg

-- | Tries to getCfg from in-memory state. If that fails, try db.
-- if db has it, add it to cache
getCfg :: CfgId -> EventLoop PilCfg
getCfg cid = CfgUI.getCfg cid >>= \case
  Just pcfg -> return pcfg
  Nothing -> getStoredCfg cid

-- | Tries to getCfg from db. if db has it, add it to cache
getStoredCfg :: CfgId -> EventLoop PilCfg
getStoredCfg cid = Db.getCfg cid >>= \case
    Nothing -> throwError . EventLoopError $ "Could not find existing CFG with id " <> show cid
    Just pcfg -> do
      CfgUI.addCfg cid pcfg
      return pcfg

sendLatestClientSnapshots :: EventLoop ()
sendLatestClientSnapshots = do
  ctx <- ask
  branches <- HashMap.toList <$> Db.getAllBranchesForClient (ctx ^. #clientId) :: EventLoop [(HostBinaryPath, [(BranchId, Snapshot.Branch Snapshot.BranchTree)])]
  sendToBinja
    . SBSnapshot
    . Snapshot.BranchesOfClient
    . fmap (over _2 (fmap (over _2 Snapshot.toTransport)))
    $ branches

sendLatestBinarySnapshots :: EventLoop ()
sendLatestBinarySnapshots = do
  ctx <- ask
  branches <- Db.getAllBranchesForBinary (ctx ^. #clientId) (ctx ^. #hostBinaryPath) :: EventLoop [(BranchId, Snapshot.Branch Snapshot.BranchTree)]
  sendToBinja
    . SBSnapshot
    . Snapshot.BranchesOfBinary (ctx ^. #hostBinaryPath)
    . fmap (over _2 Snapshot.toTransport)
    $ branches

-- | Called whenever snapshots change.
sendLatestSnapshots :: EventLoop ()
sendLatestSnapshots = sendLatestBinarySnapshots

sendLatestPois :: EventLoop ()
sendLatestPois = do
  ctx <- ask
  pois <- PoiDb.getPoisOfBinary (ctx ^. #clientId) (ctx ^. #hostBinaryPath)
  sendToBinja
    . SBPoi
    . Poi.PoisOfBinary
    $ pois

simplify :: Cfg [Pil.Stmt] -> EventLoop (Cfg [Pil.Stmt])
simplify cfg = liftIO (GSolver.simplify cfg) >>= \case
  Left err -> do
    case err of
      GSolver.SolverError tr err -> liftIO $ do
        putText "\n------------------------Type Checking Cfg-------------------------"
        putText ""
        pprint ("errors" :: Text, tr ^. #errors)
        putText ""
        prettyIndexedStmts $ tr ^. #symTypeStmts
        putText "-----------------------------------------------------------------------"
      _ -> putText . show $ err
    let (InterCfg cfg') = CfgA.simplify . InterCfg $ cfg
    return cfg'
  Right cfg' -> return cfg'

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

getTargetFunc :: BNBinaryView -> Address -> EventLoop Function
getTargetFunc bv addr = liftIO (CG.getFunction bv addr) >>= \case
  Nothing -> logError $ "Could not find function at address: " <> show addr
  Just func -> return func

-- | If active POI exists in ctx, this will convert it to a Target
-- using the bv version of the bndb to identify the function.
getActivePoiTarget :: BNBinaryView -> EventLoop (Maybe Target)
getActivePoiTarget bv = do
  ctx <- ask
  liftIO (readTVarIO $ ctx ^. #activePoi) >>= \case
    Nothing -> return Nothing
    Just poi -> do
      let addr = poi ^. #funcAddr
      -- Should this throwError if it can't find the function?
      -- That would mean whatever relies on getActivePoiTarget would also fail.
      -- If we decide it should fail, replace with:
      -- func <- getTargetFunc bv $ poi ^. #funcAddr
      liftIO (CG.getFunction bv addr) >>= \case
        Nothing -> do
          sendToBinja . SBLogError $ "Could not find function at address: " <> show addr
          return Nothing
        Just func -> do
          return . Just . Target func $ poi ^. #instrAddr

getPoiSearchResults :: BinaryHash -> PilCfg -> EventLoop (Maybe PoiSearchResults)
getPoiSearchResults bhash pcfg = do
  bv <- getBinaryView bhash
  getActivePoiTarget bv >>= \case
    Nothing -> return Nothing
    Just tgt -> do
      ctx <- ask
      -- TODO: cache the cnrCtx
      cnrCtx <- liftIO . CC.calc bhash (ctx ^. #callNodeRatingCtx)
        . CfgA.getCallNodeRatingCtx . BNImporter $ bv
      let ratings = CfgA.getCallNodeRatings cnrCtx tgt pcfg
          ratings' = fmap (over _1 $ view #uuid) . HashMap.toList $ ratings

          -- Should do we care about the Target function? or just the addr here?
          present = fmap Cfg.getNodeUUID . HashSet.toList
                    $ CfgA.getNodesContainingAddress (tgt ^. #address) pcfg
      return . Just $ PoiSearchResults ratings' present

mainEventLoop :: Event -> EventLoop ()
mainEventLoop (BinjaEvent msg) = handleBinjaEvent msg

handleBinjaEvent :: BinjaToServer -> EventLoop ()
handleBinjaEvent = \case
  BSConnect -> debug "Binja explicitly connected"
  BSTextMessage t -> do
    debug $ "Message from binja: " <> t
    sendToBinja $ SBLogInfo "Got hello. Thanks."
    sendToBinja $ SBLogInfo "Working on finding an important integer..."

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
            cfg <- simplify $ r ^. #result
            -- let (InterCfg cfg) = CfgA.simplify . InterCfg $ r ^. #result
            (_bid, cid, _snapBranch) <- Db.saveNewCfgAndBranch
              (ctx ^. #clientId)
              (ctx ^. #hostBinaryPath)
              bhash
              (func ^. #address)
              (func ^. #name)
              cfg
            CfgUI.addCfg cid cfg
            sendLatestSnapshots
            poiSearch <- getPoiSearchResults bhash cfg
            sendToBinja . SBCfg cid bhash poiSearch Nothing . convertPilCfg $ cfg
        debug "Created new branch and added auto-cfg."

  BSCfgExpandCall cid callNode targetAddr -> do
    (bv, bhash) <- getCfgBinaryView cid
    debug $ "Binja expand call for:\n" <> cs (pshow callNode)
    cfg <- getCfg cid
    case Cfg.getFullNodeMay cfg (Cfg.Call callNode) of
      Nothing ->
        sendToBinja . SBLogError $ "Could not find call node in CFG"
          -- TODO: fix issue #160 so we can just send `CallNode ()` to expandCall
      Just (Cfg.Call fullCallNode) -> do
        let bs = ICfg.mkBuilderState (BNImporter bv)
        targetFunc <- getTargetFunc bv (fromIntegral targetAddr)
        mCfg' <- liftIO . ICfg.build bs $
          ICfg.expandCall (InterCfg cfg) fullCallNode targetFunc

        case mCfg' of
          Left err ->
            -- TODO: more specific error
            sendToBinja . SBLogError . show $ err
          Right (InterCfg cfg') -> do
            simplifiedCfg <- simplify cfg'
            -- let (InterCfg simplifiedCfg) = CfgA.simplify $ InterCfg cfg'

            -- pprint . Aeson.encode . convertPilCfg $ prunedCfg
            printSimplifyStats cfg' simplifiedCfg
            autosaveCfg cid simplifiedCfg
              >>= sendCfgAndSnapshots bhash simplifiedCfg cid
      Just _ -> do
        sendToBinja . SBLogError $ "Node must be a CallNode"

  BSCfgRemoveBranch cid (node1, node2) -> do
    debug "Binja remove branch"
    -- TODO: just get the bhash since bv isn't used
    bhash <- getCfgBinaryHash cid
    cfg <- getCfg cid
    case (,) <$> Cfg.getFullNodeMay cfg node1 <*> Cfg.getFullNodeMay cfg node2 of
      Nothing -> sendToBinja
        . SBLogError $ "Node or nodes don't exist in CFG"
      Just (fullNode1, fullNode2) -> do
        let InterCfg cfg' = CfgA.prune (G.Edge fullNode1 fullNode2) $ InterCfg cfg
        printSimplifyStats cfg cfg'
        sendDiffCfg bhash cid cfg cfg'

  BSCfgRemoveNode cid node' -> do
    debug "Binja remove node"
    bhash <- getCfgBinaryHash cid
    cfg <- getCfg cid
    case Cfg.getFullNodeMay cfg node' of
      Nothing -> sendToBinja
        . SBLogError $ "Node doesn't exist in CFG"
      Just fullNode -> if fullNode == cfg ^. #root
        then sendToBinja $ SBLogError "Cannot remove root node"
        else do
          let cfg' = G.removeNode fullNode cfg
              -- InterCfg simplifiedCfg = CfgA.simplify $ InterCfg cfg'
          simplifiedCfg <- simplify cfg'
          printSimplifyStats cfg' simplifiedCfg
          sendDiffCfg bhash cid cfg simplifiedCfg

  BSCfgFocus cid node' -> do
    debug "Binja Focus"
    bhash <- getCfgBinaryHash cid
    cfg <- getCfg cid
    case Cfg.getFullNodeMay cfg node' of
      Nothing -> sendToBinja
        . SBLogError $ "Node doesn't exist in CFG"
      Just fullNode -> if fullNode == cfg ^. #root
        then sendToBinja $ SBLogError "Cannot remove root node"
        else do
          let InterCfg cfg' = CfgA.focus fullNode $ InterCfg cfg
          printSimplifyStats cfg cfg'
          sendDiffCfg bhash cid cfg cfg'

  BSCfgConfirmChanges cid ->
    CfgUI.getCfg cid >>= \case
      Nothing -> throwError . EventLoopError $ "Could not find existing CFG with id " <> show cid
      Just pcfg -> do
        bhash <- getCfgBinaryHash cid
        autosaveCfg cid pcfg
          >>= sendCfgAndSnapshots bhash pcfg cid

  BSCfgRevertChanges cid -> Db.getCfg cid >>= \case
    Nothing -> throwError . EventLoopError $ "Could not find existing CFG with id " <> show cid
    Just pcfg -> do
      CfgUI.addCfg cid pcfg
      bhash <- getCfgBinaryHash cid
      poiSearch <- getPoiSearchResults bhash pcfg
      sendToBinja . SBCfg cid bhash poiSearch Nothing $ convertPilCfg pcfg
      
    

  BSNoop -> debug "Binja noop"

  BSSnapshot snapMsg -> case snapMsg of
    Snapshot.GetAllBranchesOfClient -> sendLatestClientSnapshots

    Snapshot.GetAllBranchesOfBinary -> sendLatestBinarySnapshots

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

    Snapshot.LoadSnapshot cid -> do
      bhash <- getCfgBinaryHash cid
      cfg <- getStoredCfg cid
      poiSearch <- getPoiSearchResults bhash cfg
      sendToBinja . SBCfg cid bhash poiSearch Nothing . convertPilCfg $ cfg

    Snapshot.SaveSnapshot cid -> do
      Db.setCfgSnapshotType cid Snapshot.Immutable

      logInfo $ "Saved iCfg as immutable snapshot: " <> show cid

      sendLatestSnapshots

    Snapshot.RenameSnapshot cid name' -> do
      Db.setCfgName cid name'
      logInfo $ "Named " <> show cid <> ": \"" <> name' <> "\""
      sendLatestSnapshots

  BSPoi poiMsg' -> case poiMsg' of
    Poi.GetPoisOfBinary -> sendLatestPois

    Poi.AddPoi funcAddr instrAddr poiName poiDescription -> do
      ctx <- ask
      PoiDb.saveNew
        (ctx ^. #clientId)
        (ctx ^. #hostBinaryPath)
        funcAddr
        instrAddr
        poiName
        poiDescription
      sendLatestPois

    Poi.DeletePoi pid -> do
      PoiDb.delete pid
      sendLatestPois

    Poi.RenamePoi pid poiName -> do
      PoiDb.setName pid poiName
      sendLatestPois

    Poi.DescribePoi pid poiDescription -> do
      PoiDb.setName pid poiDescription
      sendLatestPois

    Poi.ActivatePoiSearch pid mcid -> PoiDb.getPoi pid >>= \case
      Nothing -> logError $ "Cannot find POI in database: " <> show pid
      Just poi -> do
        ctx <- ask
        liftIO . atomically . writeTVar (ctx ^. #activePoi) $ Just poi
        whenJust mcid refreshActiveCfg

    Poi.DeactivatePoiSearch mcid -> do
      ctx <- ask
      liftIO . atomically . writeTVar (ctx ^. #activePoi) $ Nothing
      whenJust mcid refreshActiveCfg

  BSConstraint constraintMsg' -> case constraintMsg' of
    C.AddConstraint cid nid stmtIndex exprText -> do
      cfg <- getCfg cid
      case Parse.run Parse.parseExpr exprText of
        Left err -> do
          putText $ "Error parsing user constraint: " <> err
          sendToBinja . SBConstraint . C.SBInvalidConstraint . C.ParseError $ err
          -- TODO: handle above message directly in binja, maybe remove below
          logWarn $ "Parse Error:\n" <> err
        Right expr -> do
          cfg' <- insertStmt cfg cid nid stmtIndex (Pil.Constraint . Pil.ConstraintOp $ expr)
          simplifiedCfg <- simplify cfg'
          -- let simplifiedCfg = unInterCfg . CfgA.simplify . InterCfg $ cfg'
          bhash <- getCfgBinaryHash cid
          sendDiffCfg bhash cid cfg' simplifiedCfg

  BSComment cid nid stmtIndex comment' -> do
    cfg <- getCfg cid
    cfg' <- insertStmt cfg cid nid stmtIndex (Pil.Annotation comment')
    bhash <- getCfgBinaryHash cid
    sendDiffCfg bhash cid cfg' cfg'

insertStmt ::
  (Eq a, Hashable a) =>
  Cfg [a] ->
  CfgId ->
  UUID ->
  Word64 ->
  a ->
  EventLoop (Cfg [a])
insertStmt cfg cid nid stmtIndex stmt = do
  node' <- getNode cfg cid nid
  (stmtsA, stmtsB) <- getStmtsAround node' stmtIndex
  let stmts' = stmtsA <> [stmt] <> stmtsB
  pure $ Cfg.setNodeData stmts' node' cfg

getNode ::
  (Eq a, Hashable a) =>
  Cfg a ->
  CfgId ->
  UUID ->
  EventLoop (CfNode a)
getNode cfg cid nid = do
  let matchingNode = filter ((== nid) . Cfg.getNodeUUID)
                      . HashSet.toList
                      . Cfg.nodes
                      $ cfg
  case matchingNode of
    [] ->
      logError $
        "getNode: could not find matching node "
        <> show nid
        <> " for Cfg "
        <> show cid
    (node':others) -> do
      unless (null others) $ do
        logWarn $
          "getNode: found multiple nodes with UUID "
          <> show nid
          <> " in Cfg "
          <> show cid
          <> ". Using first match."
      pure node'

getStmtsAround ::
  CfNode [a] ->
  Word64 ->
  EventLoop ([a], [a])
getStmtsAround node' stmtIndex = do
  let stmts = Cfg.getNodeData node'
  when (fromIntegral stmtIndex >= length stmts) $ do
    logWarn $
      "getStmtsAround: requested statement index (" <> show stmtIndex <> ")"
      <> " exceeds node's maximum statemtent index (" <> show (length stmts - 1) <> "). "
      <> "Adding to end."
  pure $ splitAt (fromIntegral stmtIndex) stmts

printSimplifyStats :: (Eq a, Hashable a, MonadIO m) => Cfg a -> Cfg a -> m ()
printSimplifyStats a b = do
  putText "------------- Simplify -----------"
  putText $ "Before: " <> show (HashSet.size $ G.nodes a) <> " nodes, "
    <> show (length $ G.edges a) <> " edges"
  putText $ "After: " <> show (HashSet.size $ G.nodes b) <> " nodes, "
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
      let er = Ch.checkIndexedStmts indexedStmts
      return $ either (Left . show) (Right . (func,)) er

