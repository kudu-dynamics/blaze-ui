{- HLINT ignore "Use if" -}
{- HLINT ignore "Reduce duplication" -}
{-# OPTIONS_GHC -Wno-deferred-out-of-scope-variables #-}

module Blaze.UI.Server where

import Blaze.UI.Prelude
import Blaze.Import.Source.BinaryNinja (BNImporter(BNImporter))
import qualified Data.Aeson as Aeson
import qualified Network.WebSockets as WS
import qualified Data.ByteString.Lazy as LBS
import qualified Data.ByteString.Char8 as BSC
import Binja.Core (BNBinaryView)
import qualified Binja.Function as BNFunc
import Blaze.UI.Types hiding ( cfg, callNode, stmtIndex,
                               startNode, groupOptions )
import qualified Data.HashMap.Strict as HashMap
import qualified Blaze.Import.Source.BinaryNinja.CallGraph as CG
import qualified Blaze.Import.Source.BinaryNinja.Pil as Pil
import qualified Blaze.Import.Source.BinaryNinja.Cfg as BnCfg
import qualified Blaze.Types.Cfg.Grouping as Cfg
import qualified Blaze.Types.Cfg as OgCfg
import qualified Blaze.Cfg as OgCfg
import Blaze.Types.Cfg.Grouping (Cfg, PilCfg, CfNode)
import qualified Blaze.Cfg.Analysis as CfgA
import qualified Blaze.Pil.Analysis as PilA
import qualified Blaze.UI.Cfg as CfgUI
import qualified Data.HashSet as HashSet
import qualified Blaze.Graph as G
import Blaze.Types.Cfg.Interprocedural (InterCfg(InterCfg))
import qualified Blaze.Cfg.Interprocedural as ICfg
import Blaze.Pretty (PIndexedStmts (..), mkTokenizerCtx, prettyIndexedStmts', pretty', showHex, pretty)
import qualified Blaze.Types.Pil.Checker as Ch
import qualified Blaze.Pil.Checker as Ch
import qualified Blaze.UI.Types.Constraint as C
import qualified Blaze.UI.Types.Cfg.Snapshot as Snapshot
import Blaze.UI.Types.Cfg.Snapshot (BranchId, Branch, BranchTree, SnapshotType)
import qualified Blaze.UI.Cfg.Snapshot as Snapshot
import Blaze.UI.Types.BndbHash (BndbHash)
import Blaze.UI.Types.BinaryHash (BinaryHash)
import qualified Blaze.UI.Db as Db
import Blaze.UI.Types.Cfg (CfgId, convertPilCfg)
import qualified Blaze.UI.BinaryManager as BM
import Blaze.UI.Types.HostBinaryPath (HostBinaryPath)
import Blaze.UI.Types.Session ( SessionId
                              , mkSessionId
                              )
import Blaze.Function (Function)
import qualified Blaze.UI.Db.Poi as PoiDb
import qualified Blaze.UI.Db.Poi.Global as GlobalPoiDb
import qualified Blaze.UI.Types.Poi as Poi
import Blaze.Types.Cfg.Analysis (Target(Target))
import qualified Blaze.UI.Types.CachedCalc as CC
import qualified Blaze.Pil.Parse as Parse
import qualified Blaze.Types.Pil as Pil
import Blaze.Types.Pil (Stmt)
import qualified Blaze.Cfg.Solver.BranchContext as GSolver


type OgCfg = OgCfg.Cfg

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

-- | Returns an existing SessionState or creates it.
getSessionState :: SessionId
                -> BinaryHash
                -> AppState
                -> IO SessionState
getSessionState sid binHash st = do
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
        ss <- emptySessionState (sid ^. #clientId) (sid ^. #hostBinaryPath) binHash bm (st ^. #dbConn) ccCallNodeRating
        modifyTVar (st ^. #binarySessions)
          $ HashMap.insert sid ss
        return (ss, True)
  when justCreated $ spawnEventHandler ss
  return ss

sendToBinja_ :: ServerToBinja -> SessionState -> IO ()
sendToBinja_ msg ss = do
  conns <- fmap HashMap.elems . readTVarIO $ ss ^. #binjaConns
  mapM_ (flip sendJSON $ BinjaMessage (ss ^. #clientId) (ss ^. #hostBinaryPath) (ss ^. #binaryHash) msg) conns

sendToBinja :: ServerToBinja -> EventLoop ()
sendToBinja msg = ask >>= liftIO . sendToBinja_ msg

-- | Websocket message handler for binja.
-- This handles messages for multiple binaries to/from single binja.
binjaApp :: AppState -> ConnId -> WS.Connection -> IO ()
binjaApp st connId conn = do
  er <- receiveJSON conn :: IO (Either Text (BinjaMessage BinjaToServer))
  case er of
    Left err -> do
      logLocalError $ "Error parsing JSON: " <> show err
    Right x -> do
      let cid = x ^. #clientId
          hpath = x ^. #hostBinaryPath
          bhash = x ^. #binaryHash
          sid = mkSessionId cid hpath
          reply = sendJSON conn . BinjaMessage cid hpath bhash
          logInfo' txt = do
            reply . SBLogInfo $ txt
            logLocalInfo txt
      ss <- getSessionState sid bhash st
      let pushEvent = atomically . writeTQueue (ss ^. #eventInbox)
            . BinjaEvent
            $ x ^. #action
      isNewConn <- atomically $ do
        sconns <- readTVar $ st ^. #sessionConns
        case HashSet.member sid <$> HashMap.lookup connId sconns of
          Just True -> return False
          _ -> do
            addSessionConn sid connId st
            modifyTVar (ss ^. #binjaConns) $ HashMap.insert connId conn
            return True
      when isNewConn . logInfo' $ "Blaze Connected for binary: " <> show hpath
      pushEvent >> binjaApp st connId conn

spawnEventHandler :: SessionState -> IO ()
spawnEventHandler ss = do
  b <- atomically . isEmptyTMVar $ ss ^. #eventHandlerThread
  case b of
    False -> logLocalWarning "spawnEventHandler -- event handler already spawned"
    True -> do
      -- spawns event handler workers for new messages
      eventTid <- forkIO . forever $ do
        msg <- atomically . readTQueue $ ss ^. #eventInbox

        void . forkIO $ do
          tid <- myThreadId
          atomically $ addWorkerThread tid ss
          void $ runEventLoop (mainEventLoop msg) ss
          atomically $ removeCompletedWorkerThread tid ss

      atomically $ putTMVar (ss ^. #eventHandlerThread) eventTid

app :: AppState -> WS.PendingConnection -> IO ()
app st pconn = case splitPath of
  ["binja"] -> WS.acceptRequest pconn >>= runBinjaApp
  _ -> do
    logLocalWarning $ "Rejected request to invalid path: " <> cs path
    WS.rejectRequest pconn $ "Invalid path: " <> path
  where
    path = WS.requestPath $ WS.pendingRequest pconn
    splitPath = drop 1 . BSC.splitWith (== '/') $ path
    runBinjaApp conn = do
      connId <- newConnId
      WS.withPingThread conn 3 (return ())
        $ catch (binjaApp st connId conn) (catchConnectionException connId)
    catchConnectionException :: ConnId -> WS.ConnectionException -> IO ()
    catchConnectionException connId e = do
      logLocalError (show e)
      cleanupClosedConn connId st

sendToAllWithBinary :: AppState -> BinaryHash -> ServerToBinja -> IO ()
sendToAllWithBinary st bh msg = do
  sss <- fmap HashMap.elems . readTVarIO $ st ^. #binarySessions
  mapM_ addToOutboxesIfBinMatches sss
  where
    addToOutboxesIfBinMatches ss
      | ss ^. #binaryHash == bh = sendToBinja_ msg ss
      | otherwise = return ()

run :: AppState -> IO ()
run st = do
  logLocalInfo $ "Starting Blaze UI Server at "
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

sendCfg :: BndbHash
        -> PilCfg
        -> CfgId
        -> Maybe PoiSearchResults
        -> Maybe PendingChanges
        -> Maybe GroupOptions
        -> EventLoop ()
sendCfg bhash cfg cid poiSearch changes groupOptions = do
  sendToBinja . SBCfg cid bhash poiSearch changes groupOptions . convertPilCfg $ cfg

sendCfgWithCallRatings :: BndbHash
                       -> PilCfg
                       -> CfgId
                       -> Maybe GroupOptions
                       -> EventLoop ()
sendCfgWithCallRatings bhash cfg cid groupOptions = do
  poiSearch <- getPoiSearchResults bhash cfg
  sendCfg bhash cfg cid poiSearch Nothing groupOptions

refreshActiveCfg :: CfgId -> EventLoop ()
refreshActiveCfg cid = do
  bhash <- getCfgBndbHash cid
  cfg <- getCfg cid
  sendCfgWithCallRatings bhash cfg cid Nothing

-- | Used after `autosaveCfg`. If second CfgId is Nothing, just send first.
-- If second is Just, send new CfgId. In both cases, send new snapshot tree.
sendCfgAndSnapshots :: BndbHash -> PilCfg -> CfgId -> Maybe CfgId -> EventLoop ()
sendCfgAndSnapshots bhash pcfg cid newCid = do
  sendCfgWithCallRatings bhash pcfg (fromMaybe cid newCid) Nothing
  sendLatestClientSnapshots

-- | Sends the old ICFG with the nodes and edges that will be removed.
-- This allows a user to confirm or deny changes
sendDiffCfg :: BndbHash -> CfgId -> PilCfg -> PilCfg -> EventLoop ()
sendDiffCfg bhash cid old new = do
  CfgUI.addCfg cid new
  if isEmptyChanges changes then
    autosaveCfg cid new >>= sendCfgAndSnapshots bhash new cid
  else
    sendCfg bhash old cid Nothing (Just changes) Nothing

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

-- | Stores the Cfg to the cache and database.
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

-- | Sends all ICFG snapshots for a particular ClientId to client.
sendLatestClientSnapshots :: EventLoop ()
sendLatestClientSnapshots = do
  ctx <- ask
  branches <- HashMap.toList <$> Db.getAllBranchesForClient (ctx ^. #clientId) :: EventLoop [(HostBinaryPath, [(BranchId, Snapshot.Branch Snapshot.BranchTree)])]
  sendToBinja
    . SBSnapshot
    . Snapshot.BranchesOfClient
    . fmap (over _2 (fmap (over _2 Snapshot.toTransport)))
    $ branches

-- | Sends all ICFG snapshots for a particular HostBinaryPath and ClientId to client.
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

-- | Sends all POIs for a binary to client.
sendLatestSessionPois :: EventLoop ()
sendLatestSessionPois = do
  ctx <- ask
  pois <- PoiDb.getPoisOfBinary (ctx ^. #clientId) (ctx ^. #hostBinaryPath)
  sendToBinja
    . SBPoi
    . Poi.PoisOfBinary
    $ pois

-- | Sends global POIs to single session.
sendGlobalPois :: EventLoop ()
sendGlobalPois = do
  ctx <- ask
  gpois <- GlobalPoiDb.getPoisOfBinary (ctx ^. #binaryHash)
  sendToBinja
    . SBPoi
    . Poi.GlobalPoisOfBinary
    $ gpois

-- | Sends global POIs to every session with that binary
broadcastGlobalPois :: AppState -> BinaryHash -> IO ()
broadcastGlobalPois st binHash = do
  pois <- flip runReaderT st $ GlobalPoiDb.getPoisOfBinary binHash
  sendToAllWithBinary st binHash . SBPoi . Poi.GlobalPoisOfBinary $ pois

-- | Converts grouped CFG into original CFG
updateCfgM :: (Ord a, Hashable a, Monad m) => (OgCfg a -> m (OgCfg a)) -> Cfg a -> m (Cfg a)
updateCfgM f cfg = do
  let (ogCfg, groupStructure) = Cfg.unfoldGroups cfg
  cfg' <- f ogCfg
  return $ Cfg.foldGroups cfg' groupStructure

-- | Simplifies the CFG by autopruning impossible edges and various passes on
-- the PIL statements, like copy propagation and phi var reduction.
-- It first tries the BranchContext pruner; if this fails, which happens
-- often due to type inference errors, it calls a non-SMT simplify which uses
-- constant propagation and can only prune constraints with constants on either side.
simplify :: OgCfg [Pil.Stmt] -> EventLoop (OgCfg [Pil.Stmt])
simplify cfg = liftIO (GSolver.simplify cfg) >>= \case
  Left err -> do
    case err of
      GSolver.SolverError tr _ -> liftIO $ do
        logLocalInfo . unlines $
          [ ""
          , "------------------------Type Checking Cfg-------------------------"
          , ""
          , cs $ pshow ("errors" :: Text, tr ^. #errors)
          , ""
          , pretty (mkTokenizerCtx cfg) . PIndexedStmts $ tr ^. #symTypeStmts
          , "-----------------------------------------------------------------------"
          ]
      _ -> logLocalError . show $ err
    let (InterCfg cfg') = CfgA.simplify . InterCfg $ cfg
    return cfg'
  Right cfg' -> return cfg'

simplify_ :: Cfg [Pil.Stmt] -> EventLoop (Cfg [Pil.Stmt])
simplify_ = updateCfgM simplify

------------------------------------------
--- main event handler

getTermUUID :: CfNode a -> UUID
getTermUUID (Cfg.Grouping n) = getTermUUID $ n ^. #termNode
getTermUUID n = Cfg.getNodeUUID n

getStartUUID :: CfNode a -> UUID
getStartUUID (Cfg.Grouping n) = getStartUUID $ n ^. #grouping . #root
getStartUUID n = Cfg.getNodeUUID n


-- | log error sends error to binja, prints to server log, and halts eventloop
-- (maybe should be named something more than "log...")
logError :: Text -> EventLoop a
logError errMsg = do
  sendToBinja . SBLogError $ errMsg
  logLocalError errMsg
  throwError $ EventLoopError errMsg

logWarn :: Text -> EventLoop ()
logWarn warnMsg = do
  sendToBinja . SBLogWarn $ warnMsg
  logLocalWarning warnMsg

logInfo :: Text -> EventLoop ()
logInfo infoMsg = do
  sendToBinja . SBLogInfo $ infoMsg
  logLocalInfo infoMsg

getCfgBinaryView :: CfgId -> EventLoop (BNBinaryView, BndbHash)
getCfgBinaryView cid = Db.getCfgBndbHash cid >>= \case
  Nothing ->
    logError $ "Could not find binary hash version for cfg: " <> show cid

  Just h -> do
    bm <- view #binaryManager <$> ask
    BM.loadBndb bm h >>= either (logError . show) (return . (,h))

getCfgBndbHash :: CfgId -> EventLoop BndbHash
getCfgBndbHash cid = Db.getCfgBndbHash cid >>= \case
  Nothing -> throwError . EventLoopError $ "getCfgBndbHash cannot find CfgId: " <> show cid
  Just h -> return h

getBinaryView :: BndbHash -> EventLoop BNBinaryView
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

getPoiSearchResults :: BndbHash -> PilCfg -> EventLoop (Maybe PoiSearchResults)
getPoiSearchResults bhash pcfg = do
  bv <- getBinaryView bhash
  getActivePoiTarget bv >>= \case
    Nothing -> return Nothing
    Just tgt -> do
      ctx <- ask
      -- TODO: cache the cnrCtx
      cnrCtx <- liftIO . CC.calc bhash (ctx ^. #callNodeRatingCtx)
        . CfgA.getCallNodeRatingCtx . BNImporter $ bv
      let (ogCfg, _) = Cfg.unfoldGroups pcfg
          ratings = CfgA.getCallNodeRatings cnrCtx tgt ogCfg
          ratings' = fmap (over _1 $ view #uuid) . HashMap.toList $ ratings

          -- Should do we care about the Target function? or just the addr here?
          present = fmap Cfg.getNodeUUID . HashSet.toList
                    $ Cfg.getNodesContainingAddress (tgt ^. #address) pcfg
      return . Just $ PoiSearchResults ratings' present

-- | Handles messages incoming from the Binja client.
-- In the future, and the past, this could handle events from other sources,
-- such as a web browser.
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
      liftIO $ threadDelay 5000000 >> logLocalInfo "calculating integer"
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
    logLocalDebug "Getting BV"
    bv <- getBinaryView bhash
    logLocalDebug "Got BV"
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
            cfg <- fmap Cfg.fromCfg . simplify $ r ^. #result
            (_bid, cid, _snapBranch) <- Db.saveNewCfgAndBranch
              (ctx ^. #clientId)
              (ctx ^. #hostBinaryPath)
              bhash
              (func ^. #address)
              (func ^. #name)
              cfg
            CfgUI.addCfg cid cfg
            sendLatestSnapshots
            sendCfgWithCallRatings bhash cfg cid Nothing
        debug "Created new branch and added auto-cfg."

  BSCfgExpandCall cid callNode targetAddr -> do
    (bv, bhash) <- getCfgBinaryView cid
    debug $ "Binja expand call for:\n" <> cs (pshow callNode)
    gcfg <- getCfg cid
    simplifiedCfg <- flip updateCfgM gcfg $ \cfg -> do
      case OgCfg.getFullNodeMay cfg (OgCfg.Call callNode) of
        Nothing ->
          logError "Could not find call node in CFG"
          -- TODO: fix issue #160 so we can just send `CallNode ()` to expandCall
        Just (OgCfg.Call fullCallNode) -> do
          let bs = ICfg.mkBuilderState (BNImporter bv)
          targetFunc <- getTargetFunc bv (fromIntegral targetAddr)

          mCfg' <- liftIO . ICfg.build bs $
            ICfg.expandCall (InterCfg cfg) fullCallNode targetFunc

          case mCfg' of
            Left err ->
              -- TODO: more specific error
              logError $ show err
            Right (InterCfg cfg') -> do
              simplifiedCfg <- simplify cfg'
              printSimplifyStats cfg' simplifiedCfg
              return simplifiedCfg
        Just _ -> do
          logError "Node must be a CallNode"
    autosaveCfg cid simplifiedCfg
      >>= sendCfgAndSnapshots bhash simplifiedCfg cid


  BSCfgRemoveBranch cid (node1, node2) -> do
    let startUUID = getStartUUID node1
        endUUID = getTermUUID node2
    debug "Binja remove branch"
    -- TODO: just get the bhash since bv isn't used
    bhash <- getCfgBndbHash cid
    gcfg <- getCfg cid
    simplifiedCfg <- flip updateCfgM gcfg $ \cfg -> do
      case (,) <$> OgCfg.findNodeByUUID startUUID cfg <*> OgCfg.findNodeByUUID endUUID cfg of
        Nothing -> logError "Node or nodes don't exist in CFG"
        Just (fullNode1, fullNode2) -> do
          let InterCfg cfg' = CfgA.prune_ (G.Edge fullNode1 fullNode2) $ InterCfg cfg
          simplifiedCfg <- simplify cfg'
          printSimplifyStats cfg simplifiedCfg
          return simplifiedCfg
    sendDiffCfg bhash cid gcfg simplifiedCfg

  BSCfgRemoveNode cid node' -> do
    debug "Binja remove node"
    bhash <- getCfgBndbHash cid
    cfg <- getCfg cid
    case Cfg.getFullNodeMay cfg node' of
      Nothing -> sendToBinja
        . SBLogError $ "Node doesn't exist in CFG"
      Just fullNode -> if fullNode == cfg ^. #root
        then sendToBinja $ SBLogError "Cannot remove root node"
        else do
          let cfg' = G.removeNode fullNode cfg
          simplifiedCfg <- flip updateCfgM cfg' $ \cfg'' -> do
            simplifiedCfg <- simplify cfg''
            printSimplifyStats cfg'' simplifiedCfg
            return simplifiedCfg
          sendDiffCfg bhash cid cfg simplifiedCfg

  BSCfgFocus cid node' -> do
    debug "Binja Focus"
    bhash <- getCfgBndbHash cid
    gcfg <- getCfg cid

    -- prettyPrint gcfg

    simplifiedCfg <- flip updateCfgM gcfg $ \cfg -> do
      case OgCfg.findNodeByUUID (getStartUUID node') cfg of
        Nothing -> logError "Node doesn't exist in CFG"
        Just fullNode -> if fullNode == cfg ^. #root
          then logError "Cannot remove root node"
          else do
            let InterCfg cfg' = CfgA.focus_ fullNode $ InterCfg cfg
            simplifiedCfg <- simplify cfg'
            printSimplifyStats cfg cfg'
            return simplifiedCfg

    sendDiffCfg bhash cid gcfg simplifiedCfg

  BSCfgConfirmChanges cid ->
    CfgUI.getCfg cid >>= \case
      Nothing -> throwError . EventLoopError $ "Could not find existing CFG with id " <> show cid
      Just pcfg -> do
        bhash <- getCfgBndbHash cid
        autosaveCfg cid pcfg
          >>= sendCfgAndSnapshots bhash pcfg cid

  BSCfgRevertChanges cid -> Db.getCfg cid >>= \case
    Nothing -> throwError . EventLoopError $ "Could not find existing CFG with id " <> show cid
    Just pcfg -> do
      CfgUI.addCfg cid pcfg
      bhash <- getCfgBndbHash cid
      sendCfgWithCallRatings bhash pcfg cid Nothing

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
      bhash <- getCfgBndbHash cid
      cfg <- getStoredCfg cid
      sendCfgWithCallRatings bhash cfg cid Nothing

    Snapshot.SaveSnapshot cid -> do
      Db.setCfgSnapshotType cid Snapshot.Immutable

      logInfo $ "Saved iCfg as immutable snapshot: " <> show cid

      sendLatestSnapshots

    Snapshot.RenameSnapshot cid name' -> do
      Db.setCfgName cid name'
      logInfo $ "Named " <> show cid <> ": \"" <> name' <> "\""
      sendLatestSnapshots

    Snapshot.PreviewDeleteSnapshot cid -> Db.previewDeleteSnapshot cid >>= \case
      Nothing -> logError "Could not find snapshot in database"
      Just p -> do
        sendToBinja . SBSnapshot $ Snapshot.DeleteSnapshotConfirmationRequest
          { snapshotRequestedForDeletion = cid
          , deletedNodes = HashSet.toList $ p ^. #deletedNodes
          , willWholeBranchBeDeleted = HashSet.member (p ^. #branchTreeRoot)
                                       $ p ^. #deletedNodes
          }

    Snapshot.ConfirmDeleteSnapshot cid -> do
      deletedCfgIds <- Db.deleteSnapshot cid
      logInfo $ "Deleted " <> show (HashSet.size deletedCfgIds) <> " snapshots."
      mapM_ CfgUI.removeCfg . HashSet.toList $ deletedCfgIds
      sendLatestSnapshots


  BSPoi poiMsg' -> case poiMsg' of
    Poi.GetPoisOfBinary -> do
      sendLatestSessionPois
      sendGlobalPois

    Poi.AddPoi funcAddr instrAddr poiName poiDescription -> do
      ctx <- ask
      PoiDb.saveNew
        (ctx ^. #clientId)
        (ctx ^. #hostBinaryPath)
        (ctx ^. #binaryHash)
        funcAddr
        instrAddr
        poiName
        poiDescription
      sendLatestSessionPois

    Poi.DeletePoi pid -> do
      PoiDb.delete pid
      sendLatestSessionPois

    Poi.RenamePoi pid poiName -> do
      PoiDb.setName pid poiName
      sendLatestSessionPois

    Poi.DescribePoi pid poiDescription -> do
      PoiDb.setName pid poiDescription
      sendLatestSessionPois

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
      case Parse.runParserEof (Parse.mkParserCtx (fst $ Cfg.unfoldGroups cfg)) Parse.parseExpr exprText of
        Left err -> do
          logLocalError $ "Error parsing user constraint: " <> err
          sendToBinja . SBConstraint . C.SBInvalidConstraint . C.ParseError $ err
          -- TODO: handle above message directly in binja, maybe remove below
          logWarn $ "Parse Error:\n" <> err
        Right expr -> do
          cfg' <- insertStmt cfg cid nid stmtIndex (Pil.Constraint . Pil.ConstraintOp $ expr)
          simplifiedCfg <- simplify_ cfg'
          bhash <- getCfgBndbHash cid
          sendDiffCfg bhash cid cfg' simplifiedCfg

  BSComment cid nid stmtIndex comment' -> do
    cfg <- getCfg cid
    cfg' <- insertStmt cfg cid nid stmtIndex (Pil.Annotation comment')
    bhash <- getCfgBndbHash cid
    sendDiffCfg bhash cid cfg' cfg'

  BSGroupStart cid nid -> do
    bhash <- getCfgBndbHash cid
    cfg <- getCfg cid
    startNode <- getNode cfg cid nid
    groupOptions <- getGroupOptions cfg startNode
    sendCfgWithCallRatings bhash cfg cid groupOptions

  BSGroupDefine cid startId endId -> do
    bhash <- getCfgBndbHash cid
    cfg <- getCfg cid
    startNode <- getNode cfg cid startId
    endNode <- getNode cfg cid endId
    -- group <- createGroup cfg startNode endNode
    -- summaryNode <- createSummaryNode cfg group
    -- cfg' <- substituteGroup cfg group summaryNode
    let cfg' = Cfg.makeGrouping startNode endNode cfg []
    autosaveCfg cid cfg'
      >>= sendCfgAndSnapshots bhash cfg' cid

    -- sendCfgWithCallRatings bhash cfg' cid Nothing

  BSGroupExpand cid groupNodeId -> do
    -- logError "Group expand not yet implemented."
    bhash <- getCfgBndbHash cid
    cfg <- getCfg cid
    getNode cfg cid groupNodeId >>= \case
      Cfg.Grouping gnode -> do
        let cfg' = Cfg.expandGroupingNode gnode cfg
        autosaveCfg cid cfg'
          >>= sendCfgAndSnapshots bhash cfg' cid
      _ -> logError "Cannot expand non-Grouping node"

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

getGroupOptions
  :: (Eq a, Hashable a)
  => Cfg [a]
  -> CfNode [a]
  -> EventLoop (Maybe GroupOptions)
getGroupOptions cfg startNode = do
  let startId = Cfg.getNodeUUID startNode
      terms = HashSet.toList $ Cfg.getPossibleGroupTerms startNode cfg
  logInfo $ "Found " <> show (length terms) <> " possible term nodes for group."
  if null terms
    then return Nothing
    else return . Just . GroupOptions startId . fmap Cfg.getNodeUUID $ terms

-- TODO: Should we check if persisting a node index would improve performance?
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

printSimplifyStats :: (Eq a, Hashable a, MonadIO m) => OgCfg a -> OgCfg a -> m ()
printSimplifyStats a b = do
  logLocalInfo . unlines $
    [ ""
    , "------------- Simplify -----------"
    , "Before: " <> show (HashSet.size $ G.nodes a) <> " nodes, "
        <> show (length $ G.edges a) <> " edges"
    , "After: " <> show (HashSet.size $ G.nodes b) <> " nodes, "
        <> show (length $ G.edges b) <> " edges"
    ]


printTypeReportToConsole :: MonadIO m => BNFunc.Function -> Ch.TypeReport -> m ()
printTypeReportToConsole fn tr = liftIO $ do
  logLocalInfo . unlines $
    [ ""
    , "------------------------Type Checking Function-------------------------"
    , cs $ pshow fn
    , ""
    , cs $ pshow ("errors" :: Text, tr ^. #errors)
    , pretty' $ tr ^. #errorConstraints
    , ""
    , pretty' . PIndexedStmts $ tr ^. #symTypeStmts
    , "-----------------------------------------------------------------------"
    ]

-- | Use on indexed statements after you've run analysis that might delete some stmts,
-- but that will leave the non-deleted stmts unchanged.
-- Turns the removed statements into comments of their pretty print.
realignIndexedStmts :: [(Int, Stmt)] -> [Stmt] -> [(Int, Stmt)]
realignIndexedStmts [] _ = []
realignIndexedStmts xs [] = xs
realignIndexedStmts ((n, x):xs) (y:ys)
  | x == y = (n, x) : realignIndexedStmts xs ys
  | otherwise = (n, Pil.Annotation $ pretty' x) : realignIndexedStmts xs (y:ys)

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
      let indexedStmts' = realignIndexedStmts indexedStmts . PilA.fixedRemoveUnusedPhi $ snd <$> indexedStmts
      -- TODO: this call to `fixedRemoveUnusedPhi` messes up the indexes
          indexedStmts'' = zip (fst <$> indexedStmts')
                           (PilA.substAddrs $ snd <$> indexedStmts')
      prettyIndexedStmts' indexedStmts''
      let er = Ch.checkIndexedStmts indexedStmts''
      return $ either (Left . show) (Right . (func,)) er
