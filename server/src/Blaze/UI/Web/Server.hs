module Blaze.UI.Web.Server where

import Blaze.UI.Prelude hiding (get)

import Blaze.UI.Types hiding (cfg)
import qualified Blaze.UI.Types.BinaryHash as BinaryHash
import qualified Blaze.UI.Types.BinaryManager as BM
import Blaze.UI.Types.HostBinaryPath (HostBinaryPath)
import qualified Blaze.UI.Types.HostBinaryPath as HBP
import Blaze.UI.Types.Session (ClientId)

import Data.List (lookup)
import qualified Data.Text.Lazy
import qualified Network.Wai.Parse as Wai
import Web.Scotty (ActionM, File, ScottyM, files, get, json, post, scotty, setHeader)
import Web.Scotty.Trans (ActionT, Parsable (parseParam), ScottyError (stringError), html, params)

server :: ServerConfig -> ScottyM ()
server cfg = do
  get "/" showErrorPage
  post "/upload" $ uploadBinary cfg

-- | Same as 'Web.Scotty.Trans.param' but do not call
-- 'Web.Scotty.Trans.next' if it fails to parse. Instead, throw an error
requiredParam :: (Parsable a, ScottyError e, Monad m) => Data.Text.Lazy.Text -> ActionT e m a
requiredParam k = do
    ps <- params
    case lookup k ps of
        Nothing -> throwError . stringError $ "Param: " ++ cs k ++ " not found!"
        Just v  -> either (throwError . stringError . cs) return $ parseParam v

uploadBinary :: ServerConfig -> ActionM ()
uploadBinary cfg = do
  (hostBinaryPath' :: HostBinaryPath) <- requiredParam "hostBinaryPath" --used for identification
  (clientId' :: ClientId) <- requiredParam "clientId"
  files >>= mapM_ (saveBndb clientId' hostBinaryPath')
  where
    saveBndb :: ClientId -> HostBinaryPath -> File -> ActionM ()
    saveBndb clientId' hostBinaryPath' ("bndb", finfo) = do
      h <- BM.saveBndbBytestring (cfg ^. #binaryManagerStorageDir) clientId' hostBinaryPath'
        . cs
        . Wai.fileContent
        $ finfo
      json h
      putText $ "New bndb uploaded: "
        <> HBP.toText hostBinaryPath'
        <> " (" <> BinaryHash.toText h <> ")"
    saveBndb _ _ _ = return ()

showErrorPage :: ActionM ()
showErrorPage = do
  setHeader "Content-Type" "text/html"
  html "This is the best page <i>ever</i>"

run :: ServerConfig -> IO ()
run cfg = do
  putText $ "Starting http server at http://" <> serverHost cfg <> ":"
    <> show (serverHttpPort cfg)
  scotty (serverHttpPort cfg) $ server cfg
