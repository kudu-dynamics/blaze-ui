module Main where

import Blaze.UI.Prelude
import qualified Prelude as P
import Blaze.Util.MLIL
import qualified Data.Text as Text
import qualified Blaze.UI.Server as Server
import Blaze.UI.Server (ServerConfig(ServerConfig))

main :: IO ()
main = getArgs >>= \case
  [host, port] -> Server.run $ ServerConfig (cs host) (P.read port)
  _ -> putText "blaze_ui_server [host] [port]"

