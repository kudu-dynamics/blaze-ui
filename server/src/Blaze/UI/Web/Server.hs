module Blaze.UI.Web.Server where

import Blaze.UI.Prelude hiding (get)

import Blaze.UI.Types hiding (cfg)
import Web.Scotty ( ScottyM
                  , ActionM
                  , get
                  , file
                  , setHeader
                  , html
                  , scotty
                  , capture
                  , param
                  )
import qualified Data.Text.IO as TIO

server :: ServerConfig -> ScottyM ()
server cfg = do
  get "/" showErrorPage
  get "/js/main.js" $ file "./res/js/main.js"
  get (capture "/:sid") $ showUI cfg

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
