module Main where

import Blaze.UI.Prelude
import qualified Prelude as P
import qualified Blaze.UI.Server as Server
import Blaze.UI.Types (ServerConfig(ServerConfig))
import Blaze.UI.Web.Server as WebServer
import qualified System.Envy as Envy
import System.IO ( BufferMode(LineBuffering)
                 , hSetBuffering)


main :: IO ()
main = do
  hSetBuffering stdout LineBuffering
  cfg <- getArgs >>= \case
    [] -> (Envy.decodeEnv :: IO (Either String ServerConfig)) >>= either P.error return

  [host, wsPort, httpPort, sliteFilePath, bndbDir ] -> return $ ServerConfig (cs host) (P.read wsPort) (P.read httpPort) sqliteFilePath bndbDir
    _ -> do
      putText "BLAZE_UI_HOST='localhost' BLAZE_UI_WS_PORT='1234' BLAZE_UI_HTTP_PORT='2345' BLAZE_UI_SQLITE_FILEPATH='blaze.sqlite` blaze-ui-server"
      putText "or"
      putText "blaze-ui-server [host] [websockets port] [http port] [sqlite filepath] [bndb dir]"
      P.error "Invalid args"
  void . forkIO $ WebServer.run cfg
  Server.run cfg
