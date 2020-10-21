{-# LANGUAGE TemplateHaskell #-}
module Blaze.UI.Server where

import Blaze.UI.Prelude
import qualified Prelude as P
import Data.Aeson (FromJSON, ToJSON)
import qualified Data.Aeson as Aeson
import qualified Network.WebSockets as WS
import qualified System.Envy as Envy
import System.Envy (fromEnv, FromEnv)
import qualified Data.ByteString.Lazy as LBS
-- import Control.Concurrent (threadDelay)
import Control.Concurrent.STM.TQueue (newTQueueIO, TQueue, readTQueue, newTQueue, writeTQueue)
import Control.Concurrent.STM.TVar (newTVarIO, TVar, readTVar, modifyTVar)
import Control.Concurrent.STM.TMVar (TMVar, readTMVar, newEmptyTMVar, putTMVar)
import Binja.Core (BNBinaryView)
import qualified Binja.Core as BN
import qualified Web.Hashids as Hashids
import Blaze.UI.Types
import Control.Concurrent.Async (wait, async)
import qualified Data.HashMap.Strict as HashMap

receiveJSON :: FromJSON a => WS.Connection -> IO (Either Text a)
receiveJSON conn = do
  x <- WS.receiveData conn :: IO LBS.ByteString
  return . first cs . Aeson.eitherDecode $ x

sendJSON :: ToJSON a => WS.Connection -> a -> IO ()
sendJSON conn x =
  WS.sendTextData conn (Aeson.encode x :: LBS.ByteString)


-- | returns session state or creates it.
-- bool indicates whether or not it was just now created
getSessionState :: SessionId -> AppState ->  IO (Bool, SessionState)
getSessionState sid st = do
  atomically $ do
    m <- readTVar $ st ^. binarySessions
    case HashMap.lookup sid m of
      Just ss -> return (False, ss)
      Nothing -> do
        ss <- emptySessionState
        modifyTVar (st ^. binarySessions) $ HashMap.insert sid ss
        return (True, ss)

createOutbox :: SessionState -> IO

-- | Websocket message handler for binja.
-- This handles messages for multiple binaries to/from single binja.
-- connOutboxThreads is needed to store if an outbox thread has already been
-- started for this particular binja conn, since there might already be an outbox
-- to a different binja.
binjaApp :: HashMap SessionId ThreadId -> AppState -> WS.Connection -> IO ()
binjaApp connOutboxThreads st conn = do
  er <- receiveJSON conn :: IO (Either Text (BinjaMessage BinjaToServer))
  case er of
    Left err -> do
      putText $ "Error parsing JSON: " <> show err
    Right x -> do
      let fp = x ^. bvFilePath
          sid = binaryPathToSessionId fp
          reply = sendJSON conn . BinjaMessage fp
          storeEvent = atomically . writeTQueue (ss ^. eventInbox)
                       . BinjaEvent $ x ^. action
      (justCreated, ss) <- getSessionState sid st
      case justCreated of
        False -> do
          -- check to see if this conn has registered outbox thread
          case HashMap.member sid connOutboxThreads of
            False -> do
              (outboxThread, outboxQueue) <- createOutbox ss sid fp
              storeEvent
              binjaApp (HashMap.insert outboxThread outboxQueue connOutboxThreads) st conn
            True -> storeEvent >> binjaApp connOutboxThreads st conn
        True -> do
          putText $ "New Binja Connection for bin: " <> fp
          reply . SBLogInfo $ "Blaze Connected. Loading binary: " <> fp
          ebv <- BN.getBinaryView . cs $ fp
          case ebv of
            Left err -> do
              reply . SBLogError $ "Blaze cannot open binary: " <> err
              atomically . modifyTVar (st ^. binarySessions) $ HashMap.delete sid
              return ()
            Right bv -> do
              atomically $ putTMVar (ss ^. binaryView) bv
              outbox <- newTQueueIO
              outboxThread <- forkIO . forever $ do
                outMsg <- atomically . readTQueue $ outbox
                reply outMsg
              atomically . modifyTVar (ss ^. binjaOutboxes)
                $ HashMap.insert outboxThread outbox
              undefined          
            
  binjaApp st conn

webApp :: WS.Connection -> IO ()
webApp conn = do
  er <- receiveJSON conn :: IO (Either Text (BinjaMessage WebToServer))
  case er of
    Left err -> do
      putText $ "Error parsing JSON: " <> show err
    Right x -> do
      putText $ "Got message: " <> show x
      -- putText $ "Sleeping 2s before sending reply"
      -- threadDelay 2000000
      let outMsg =  BinjaMessage (_bvFilePath x) $
            WSTextMessage "I got your message, web loser."
      sendJSON conn outMsg
      putText $ "Sent reply: " <> show outMsg
  webApp conn

  

app :: AppState -> WS.PendingConnection -> IO ()
app st pconn = case WS.requestPath $ WS.pendingRequest pconn of
  "binja" -> WS.acceptRequest pconn >>= binjaApp st
  "web" -> WS.acceptRequest pconn >>= webApp
  path -> WS.rejectRequest pconn $ "Invalid path: " <> path

-- data AppState = AppState
--   { _binarySessions :: HashMap SessionId SessionState }

run :: ServerConfig -> IO ()
run cfg = do
  st <- emptyAppState
  WS.runServer (cs $ serverHost cfg) (serverPort cfg) (app st)



main :: IO ()
main = (Envy.decodeEnv :: IO (Either String ServerConfig))
  >>= either P.error run
  


testClient :: BinjaMessage BinjaToServer -> WS.Connection -> IO (BinjaMessage ServerToBinja)
testClient msg conn = do
  sendJSON conn msg
  (Right r) <- receiveJSON conn
  return r

runClient :: ServerConfig -> (WS.Connection -> IO a) -> IO a
runClient cfg = WS.runClient (cs $ serverHost cfg) (serverPort cfg) ""


mainEventLoop :: Event -> EventLoop ()
mainEventLoop = undefined


