module Main where

import Blaze.UI.Prelude
import qualified Prelude as P
import qualified Blaze.UI.Server as Server
import Blaze.UI.Types (ServerConfig(ServerConfig), initAppState)
import Blaze.UI.Web.Server as WebServer
import qualified System.Envy as Envy
import System.IO ( BufferMode(LineBuffering)
                 , hSetBuffering)
import qualified Blaze.UI.Types.BinaryManager as BM
import qualified Blaze.UI.Db as Db
import GHC.Conc (numCapabilities)


main :: IO ()
main = do
  hSetBuffering stdout LineBuffering
  cfg <- getArgs >>= \case
    [] -> (Envy.decodeEnv :: IO (Either String ServerConfig)) >>= either P.error return

    [host, wsPort, httpPort, sqliteFilePath, bndbDir ] -> return $ ServerConfig (cs host) (P.read wsPort) (P.read httpPort) sqliteFilePath (BM.BinaryManagerStorageDir bndbDir)
    _ -> do
      putText "USAGE:"
      putText "BLAZE_UI_HOST=localhost BLAZE_UI_WS_PORT=1234 BLAZE_UI_HTTP_PORT=2345 BLAZE_UI_SQLITE_FILEPATH=blaze.sqlite BLAZE_UI_BNDB_STORAGE_DIR=/opt/blaze blaze-ui-server"
      putText "or"
      putText "blaze-ui-server <host> <websockets port> <http port> <sqlite filepath> <bndb dir>"
      P.error "Invalid args"

  usedCapabilities <- getNumCapabilities
  putStrLn @Text
    $ "User specified " <> show numCapabilities <> " capabilities; server using "
    <> show usedCapabilities <> " capabilities."

  conn <- Db.init $ cfg ^. #sqliteFilePath

  appState <- initAppState cfg conn

  r <- catches (race (WebServer.run appState) (Server.run appState))
    [ Handler $ \(err :: AsyncException) -> case err of
        UserInterrupt -> do
          putText $ "User Interrupt"
          shutdown ExitSuccess conn
        _ -> do
          putText $ "Fatal async exception: " <> show err
          shutdown (ExitFailure $ (-1)) conn
    , Handler $ \(err :: SomeException) -> do
        putText $ "Fatal exception: " <> show err
        shutdown (ExitFailure (-1)) conn
    ]

  case r of
    Left _ -> do
      putText "Error: Webserver exited prematurely."
      shutdown (ExitFailure (-1)) conn
    Right _ -> do
      putText "Error: Websocket server exited prematurely."
      shutdown (ExitFailure (-1)) conn

shutdown :: ExitCode -> Db.Conn -> IO a
shutdown exitCode conn = do
  putText "Shutting down Blaze"
  putText "Closing database connection"
  Db.close conn
  exitWith exitCode
  
