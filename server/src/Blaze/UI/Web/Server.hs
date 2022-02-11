module Blaze.UI.Web.Server where

import Blaze.UI.Prelude hiding (get)
import qualified Prelude as P

import Blaze.UI.Types hiding (cfg)
import qualified Blaze.UI.Types.BinaryHash as BinaryHash
import qualified Blaze.UI.BinaryManager as BM
import Blaze.UI.Types.HostBinaryPath (HostBinaryPath)
import qualified Blaze.UI.Types.HostBinaryPath as HBP
import Blaze.UI.Types.Session (ClientId, mkSessionId)
import Blaze.UI.Server (getSessionState)
import qualified Blaze.UI.Types.CachedCalc as CC
import qualified Blaze.Cfg.Analysis as CfgA
import Blaze.Import.Source.BinaryNinja (BNImporter(BNImporter))

import Data.List (lookup)
import qualified Data.Text.Lazy
import qualified Network.Wai.Parse as Wai
import Web.Scotty (ActionM, File, ScottyM, files, get, json, post, scotty, setHeader)
import Web.Scotty.Trans (ActionT, Parsable (parseParam), ScottyError (stringError), html, params, raiseStatus)
import Network.HTTP.Types (badRequest400)


server :: AppState -> ScottyM ()
server st = do
  get "/" showErrorPage
  post "/upload" $ uploadBinary st

-- | Same as 'Web.Scotty.Trans.param' but do not call
-- 'Web.Scotty.Trans.next' if it fails to parse. Instead, throw an error
requiredParam :: (Parsable a, ScottyError e, Monad m) => Data.Text.Lazy.Text -> ActionT e m a
requiredParam k = do
    ps <- params
    case lookup k ps of
        Nothing -> raiseStatus badRequest400 . stringError $ "Missing param: " ++ cs k
        Just v  -> either (raiseStatus badRequest400 . stringError . cs) return $ parseParam v

uploadBinary :: AppState -> ActionM ()
uploadBinary st = do
  (hostBinaryPath' :: HostBinaryPath) <- requiredParam "hostBinaryPath" --used for identification
  (clientId' :: ClientId) <- requiredParam "clientId"
  files >>= mapM_ (saveBndb clientId' hostBinaryPath')
  where
    cfg = st ^. #serverConfig
    saveBndb :: ClientId -> HostBinaryPath -> File -> ActionM ()
    saveBndb clientId' hostBinaryPath' ("bndb", finfo) = do
      h <- BM.saveBndbBytestring (cfg ^. #binaryManagerStorageDir) clientId' hostBinaryPath'
        . cs
        . Wai.fileContent
        $ finfo

      let sid = mkSessionId clientId' hostBinaryPath'
      ss <- liftIO $ getSessionState sid st
      bv <- BM.loadBndb (ss ^. #binaryManager) h >>= \case
        Left err -> P.error $ "Could not open recently uploaded bndb. " <> show err
        Right bv -> return bv

      void . liftIO
        . CC.setCalc h (ss ^. #callNodeRatingCtx)
        $ do
            r <- CfgA.getCallNodeRatingCtx $ BNImporter bv
            putText "Calculated CallNodeRatingCtx."
            return r
      json h
      putText $ "New bndb uploaded: "
        <> HBP.toText hostBinaryPath'
        <> " (" <> BinaryHash.toText h <> ")"
    saveBndb _ _ _ = return ()

showErrorPage :: ActionM ()
showErrorPage = do
  setHeader "Content-Type" "text/html"
  html "This is the best page <i>ever</i>"

run :: AppState -> IO ()
run st = do
  putText $ "Starting http server at http://" <> serverHost cfg <> ":"
    <> show (serverHttpPort cfg)
  scotty (serverHttpPort cfg) $ server st
  where
    cfg = st ^. #serverConfig
