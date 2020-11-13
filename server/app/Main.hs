module Main where

import Blaze.UI.Prelude
import qualified Prelude as P
import qualified Blaze.UI.Server as Server
import Blaze.UI.Types (ServerConfig(ServerConfig))
import Blaze.UI.Web.Server as WebServer
import qualified System.Envy as Envy


main :: IO ()
main = do
  cfg <- getArgs >>= \case
    [] -> (Envy.decodeEnv :: IO (Either String ServerConfig)) >>= either P.error return

    [host, wsPort, httpPort ] -> return $ ServerConfig (cs host) (P.read wsPort) (P.read httpPort)
    _ -> do
      putText "BLAZE_UI_HOST='localhost' BLAZE_UI_PORT='1234' blaze_ui_server"
      putText "or"
      putText "blaze_ui_server [host] [websockets port] [http port]"
      P.error "Invalid args"
  void . forkIO $ WebServer.run cfg
  Server.run cfg
