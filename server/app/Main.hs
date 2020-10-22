module Main where

import Blaze.UI.Prelude
import qualified Prelude as P
import qualified Blaze.UI.Server as Server
import Blaze.UI.Types (ServerConfig(ServerConfig))

main :: IO ()
main = getArgs >>= \case
  [] -> Server.main
  [host, port] -> Server.run $ ServerConfig (cs host) (P.read port)
  _ -> do
    putText "BLAZE_UI_HOST='localhost' BLAZE_UI_PORT='1234' blaze_ui_server"
    putText "or"
    putText "blaze_ui_server [host] [port]"

