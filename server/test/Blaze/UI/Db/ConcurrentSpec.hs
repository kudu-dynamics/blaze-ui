module Blaze.UI.Db.ConcurrentSpec where

-- Tests Selda concurrency

import qualified Prelude as P
import Blaze.UI.Prelude hiding (ignore)
import System.IO.Temp (emptySystemTempFile)
import Test.Hspec
import Database.Selda
import Database.Selda.SQLite
import Database.Selda.Backend (runSeldaT)
import Control.Concurrent.Async (replicateConcurrently_)

type DataId = Int

data SimpleData = SimpleData
  { dataId :: DataId
  , counter :: Int
  } deriving (Generic, SqlRow)

simpleTable :: Table SimpleData
simpleTable = table "simple" [#dataId :- primary]

simpleCreateEntry :: SeldaM b DataId
simpleCreateEntry = do
  id <- liftIO randomIO
  insert_ simpleTable [ SimpleData id 0 ]
  return id

simpleAdd1 :: DataId -> SeldaM b ()
simpleAdd1 id = do
  update_ simpleTable
    (\x -> x ! #dataId .== literal id)
    (\x -> x `with` [#counter += 1])

simpleResult :: DataId -> SeldaM b Int
simpleResult id = do
  r <- query $ do
    x <- select simpleTable
    restrict (x ! #dataId .== literal id)
    return (x ! #counter)
  case r of
    [] -> P.error "SimpleResult: No results"
    [x] -> return x
    _ -> P.error "SimpleResult: Multiple results"


initDb :: FilePath -> IO ()
initDb db = do
  withSQLite db $ do
    createTable simpleTable

-- fails
simpleTest :: FilePath -> IO Int
simpleTest db = do
  initDb db
  id <- withSQLite db simpleCreateEntry
  withSQLite db $ simpleAdd1 id
  replicateConcurrently_ 10 $ f id
  -- void . forkIO $ replicateM_ 10 $ f id
  threadDelay 100000
  withSQLite db $ simpleResult id
  where
    f id = replicateM_ 10 $ do
      -- void . withSQLite db $ simpleResult id
      withSQLite db $ simpleAdd1 id

simpleTest2 :: FilePath -> IO Int
simpleTest2 db = do
  initDb db
  conn <- sqliteOpen db
  
  id <- runSeldaT simpleCreateEntry conn
  replicateConcurrently_ 10 $ f conn id
  r <- runSeldaT (simpleResult id) conn
  seldaClose conn
  return r
  where
    f conn id = replicateM_ 5 $ do
      runSeldaT (simpleAdd1 id) conn

spec :: Spec
spec = describe "Blaze.UI.Db.Concurrent" $ do
  context "Selda" $ do
    r <- runIO $ emptySystemTempFile "jimmy" >>= simpleTest2
    it "Should handle single connection shared accross multiple writes" $ do
      r `shouldBe` 50
