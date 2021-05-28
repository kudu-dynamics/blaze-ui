module Blaze.UI.Web.Server where

import Blaze.UI.Prelude hiding (get)

import Blaze.UI.Types hiding (cfg)
import Web.Scotty ( ScottyM
                  , ActionM
                  , File
                  , get
                  , post
                  , file
                  , files
                  , json
                  , setHeader
                  , html
                  , scotty
                  -- , capture
                  , param
                  -- , text
                  )
-- import qualified Data.Text.IO as TIO
-- import qualified Data.ByteString as BS
import qualified Network.Wai.Parse as Wai
-- import System.Directory (doesFileExist)
-- import Blaze.UI.Types.BinaryHash (BinaryHash)
import qualified Blaze.UI.Types.BinaryHash as BinaryHash
import qualified Blaze.UI.Types.BinaryManager as BM
import Blaze.UI.Types.Session (ClientId)
import Blaze.UI.Types.HostBinaryPath (HostBinaryPath)
import qualified Blaze.UI.Types.HostBinaryPath as HBP

server :: ServerConfig -> ScottyM ()
server cfg = do
  get "/" showErrorPage
  post "/upload" $ uploadBinary cfg
  -- post (capture "/upload/:binaryname/:binaryhash)") $ uploadBinary cfg
  get "/js/main.js" $ file "./res/js/main.js"
  -- get (capture "/:sid") $ showUI cfg


-- curl to upload example file:
-- curl -X POST -F 'binaryName=exampleBin' -F 'binaryHash=1234' -F 'bndb=@/tmp/example.bndb' http://localhost:31338/upload

uploadBinary :: ServerConfig -> ActionM ()
uploadBinary cfg = do
  (hostBinaryPath' :: HostBinaryPath) <- param "hostBinaryPath" --used for identification
  (clientId' :: ClientId) <- param "clientId"
  -- putText $ "You got a file, " <> binaryName <> " " <> show binaryHash
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

-- showUI :: ServerConfig -> ActionM ()
-- showUI cfg = do
--   setHeader "Content-Type" "text/html"
--   body <- liftIO $ TIO.readFile "res/client_ui_body.html"
--   (sid :: SessionId) <- param "sid"
--   html $ header sid <> cs body <> footer
--   where
--     tag t contents = "<" <> t <> ">" <> contents <> "</" <> t <> ">"
--     script = tag "script"
--     header sid = "<html><head>" <> script (jsVars sid) <> "</head>"

--     jsVars (SessionId sid) = "sessionId = '" <> cs sid <> "';\n"
--       <> "blazeServerHost = '" <> cs (serverHost cfg) <> "';\n"
--       <> "blazeServerWsPort = '" <> show (serverWsPort cfg) <> "';"
    
--     footer = "</html>"

showErrorPage :: ActionM ()
showErrorPage = do
  setHeader "Content-Type" "text/html"
  html "This is the best page <i>ever</i>"

run :: ServerConfig -> IO ()
run cfg = do
  putText $ "Starting http server at http://" <> serverHost cfg <> ":"
    <> show (serverHttpPort cfg)
  scotty (serverHttpPort cfg) $ server cfg
