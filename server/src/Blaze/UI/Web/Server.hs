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
                  , setHeader
                  , html
                  , scotty
                  , capture
                  , param
                  )
import qualified Data.Text.IO as TIO
import qualified Data.ByteString as BS
import qualified Network.Wai.Parse as Wai
import System.Directory (doesFileExist)

server :: ServerConfig -> ScottyM ()
server cfg = do
  get "/" showErrorPage
  post "/upload" $ uploadBinary cfg
  -- post (capture "/upload/:binaryname/:binaryhash)") $ uploadBinary cfg
  get "/js/main.js" $ file "./res/js/main.js"
  get (capture "/:sid") $ showUI cfg


uploadBinary :: ServerConfig -> ActionM ()
uploadBinary cfg = do
  (binaryName :: FilePath) <- param "binaryName"
  (binaryHash :: Int) <- param "binaryHash"
  -- putText $ "You got a file, " <> binaryName <> " " <> show binaryHash
  files >>= mapM_ (saveBndb binaryName binaryHash)
  where
    saveBndb :: FilePath -> Int -> File -> ActionM ()
    saveBndb bname bhash ("bndb", finfo) = liftIO (doesFileExist fpath) >>= \case
      True -> return ()
      False -> liftIO . BS.writeFile fpath . cs $ Wai.fileContent finfo
      where
        fname :: FilePath
        fname = cs bname <> "_" <> show bhash <> ".bndb"
        fpath :: FilePath
        fpath = cfg ^. #bndbDir <> "/" <> fname
    saveBndb _ _ _ = return ()

showUI :: ServerConfig -> ActionM ()
showUI cfg = do
  setHeader "Content-Type" "text/html"
  body <- liftIO $ TIO.readFile "res/client_ui_body.html"
  (sid :: SessionId) <- param "sid"
  html $ header sid <> cs body <> footer
  where
    tag t contents = "<" <> t <> ">" <> contents <> "</" <> t <> ">"
    script = tag "script"
    header sid = "<html><head>" <> script (jsVars sid) <> "</head>"

    jsVars (SessionId sid) = "sessionId = '" <> cs sid <> "';\n"
      <> "blazeServerHost = '" <> cs (serverHost cfg) <> "';\n"
      <> "blazeServerWsPort = '" <> show (serverWsPort cfg) <> "';"
    
    footer = "</html>"

showErrorPage :: ActionM ()
showErrorPage = do
  setHeader "Content-Type" "text/html"
  html "This is the best page <i>ever</i>"

run :: ServerConfig -> IO ()
run cfg = do
  putText $ "Starting http server at http://" <> serverHost cfg <> ":"
    <> show (serverHttpPort cfg)
  scotty (serverHttpPort cfg) $ server cfg
