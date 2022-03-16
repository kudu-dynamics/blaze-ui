module Blaze.UI.Web.Server where

import Blaze.UI.Prelude hiding (get, put)
import qualified Prelude as P

import Blaze.UI.Types hiding (cfg)
import qualified Blaze.UI.Types.BndbHash as BndbHash
import Blaze.UI.Types.BinaryHash (BinaryHash)
import qualified Blaze.UI.BinaryManager as BM
import Blaze.UI.Types.HostBinaryPath (HostBinaryPath)
import qualified Blaze.UI.Types.HostBinaryPath as HBP
import Blaze.UI.Types.Session (ClientId, mkSessionId)
import Blaze.UI.Server (getSessionState, sendToAllWithBinary)
import qualified Blaze.UI.Types.CachedCalc as CC
import qualified Blaze.Cfg.Analysis as CfgA
import Blaze.Import.Source.BinaryNinja (BNImporter(BNImporter))
import qualified Blaze.UI.Db.Poi.Global as GlobalPoi
import Blaze.UI.Types.Poi (ServerToBinja(GlobalPoisOfBinary))

import Data.List (lookup)
import qualified Data.Text.Lazy
import qualified Data.Text.IO as TextIO
import qualified Data.ByteString.Lazy as LB
import qualified Network.Wai.Parse as Wai
import Web.Scotty (ActionM, File, ScottyM, body, files, get, json, post, put, raw, scotty, setHeader)
import Web.Scotty.Trans (ActionT, Parsable (parseParam), ScottyError (stringError), html, params, raiseStatus)
import Network.HTTP.Types (badRequest400)


server :: AppState -> ScottyM ()
server st = do
  get "/" showErrorPage
  post "/ping" ping
  post "/upload" $ uploadBinary st
  get "/poi" $ submitPoi st
  post "/poi" $ submitPoi st
  put "/poi" $ submitPoi st
  get "/demo/poi/set" $ htmlFile "res/html/poiset.html"

htmlFile :: FilePath -> ActionM ()
htmlFile = html . cs <=< liftIO . TextIO.readFile

-- | Responds with the first 64 bytes of the request body
ping :: ActionM ()
ping = do
  raw . LB.take 64 =<< body

-- | Same as 'Web.Scotty.Trans.param' but do not call
-- 'Web.Scotty.Trans.next' if it fails to parse. Instead, throw an error
requiredParam :: (Parsable a, ScottyError e, Monad m) => Data.Text.Lazy.Text -> ActionT e m a
requiredParam k = do
    ps <- params
    case lookup k ps of
        Nothing -> raiseStatus badRequest400 . stringError $ "Missing param: " ++ cs k
        Just v  -> either (raiseStatus badRequest400 . stringError . cs) return $ parseParam v

optionalParam :: (Parsable a, ScottyError e, Monad m) => Data.Text.Lazy.Text -> ActionT e m (Maybe a)
optionalParam k = do
    ps <- params
    case lookup k ps of
        Nothing -> return Nothing
        Just v  -> either (raiseStatus badRequest400 . stringError . cs) (return . Just) $ parseParam v

uploadBinary :: AppState -> ActionM ()
uploadBinary st = do
  (hostBinaryPath' :: HostBinaryPath) <- requiredParam "hostBinaryPath" --used for identification
  (binaryHash' :: BinaryHash) <- requiredParam "binaryHash"
  (clientId' :: ClientId) <- requiredParam "clientId"
  files >>= mapM_ (saveBndb clientId' hostBinaryPath' binaryHash')
  where
    cfg = st ^. #serverConfig
    saveBndb :: ClientId -> HostBinaryPath -> BinaryHash -> File -> ActionM ()
    saveBndb clientId' hostBinaryPath' binaryHash' ("bndb", finfo) = do
      h <- BM.saveBndbBytestring (cfg ^. #binaryManagerStorageDir) clientId' hostBinaryPath'
        . cs
        . Wai.fileContent
        $ finfo

      let sid = mkSessionId clientId' hostBinaryPath'
      ss <- liftIO $ getSessionState sid binaryHash' st
      bv <- BM.loadBndb (ss ^. #binaryManager) h >>= \case
        Left err -> P.error $ "Could not open recently uploaded bndb. " <> show err
        Right bv -> return bv
      void . liftIO
        . CC.setCalc h (ss ^. #callNodeRatingCtx)
        $ do
            r <- CfgA.getCallNodeRatingCtx $ BNImporter bv
            logLocalInfo "Calculated CallNodeRatingCtx."
            return r
      json h
      logLocalInfo $ "New bndb uploaded: "
        <> HBP.toText hostBinaryPath'
        <> " (" <> BndbHash.toText h <> ")"
    saveBndb _ _ _ _ = return ()

submitPoi :: AppState -> ActionM ()
submitPoi st = do
  (binHash :: BinaryHash) <- requiredParam "binaryHash"
  (funcAddr :: Address) <- requiredParam "funcAddr"
  (instrOffset :: Bytes) <- requiredParam "instrOffset"
  (poiName :: Maybe Text) <- optionalParam "name"
  (description :: Maybe Text) <- optionalParam "description"
  pois <- liftIO . flip runReaderT st $ do
    GlobalPoi.saveNew binHash funcAddr instrOffset poiName description
    GlobalPoi.getPoisOfBinary binHash
  liftIO . sendToAllWithBinary st binHash . SBPoi . GlobalPoisOfBinary $ pois
  return ()

showErrorPage :: ActionM ()
showErrorPage = do
  setHeader "Content-Type" "text/html"
  html "This is the best page <i>ever</i>"

run :: AppState -> IO ()
run st = do
  logLocalInfo $ "Starting http server at http://" <> serverHost cfg <> ":"
    <> show (serverHttpPort cfg)
  scotty (serverHttpPort cfg) $ server st
  where
    cfg = st ^. #serverConfig
