module Blaze.UI.Web.Server where

import Blaze.UI.Prelude hiding (get)

import Blaze.UI.Types hiding (cfg)
import Web.Scotty ( ScottyM
                  , ActionM
                  , File
                  , get
                  , post
                  , files
                  , json
                  , setHeader
                  , html
                  , scotty
                  , param
                  )
import qualified Network.Wai.Parse as Wai
import qualified Blaze.UI.Types.BinaryHash as BinaryHash
import qualified Blaze.UI.Types.BinaryManager as BM
import Blaze.UI.Types.Session (ClientId)
import Blaze.UI.Types.HostBinaryPath (HostBinaryPath)
import qualified Blaze.UI.Types.HostBinaryPath as HBP


server :: ServerConfig -> ScottyM ()
server cfg = do
  get "/" showErrorPage
  post "/upload" $ uploadBinary cfg

uploadBinary :: ServerConfig -> ActionM ()
uploadBinary cfg = do
  (hostBinaryPath' :: HostBinaryPath) <- param "hostBinaryPath" --used for identification
  (clientId' :: ClientId) <- param "clientId"
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
