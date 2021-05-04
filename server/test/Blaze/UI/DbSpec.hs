module Blaze.UI.DbSpec where

import qualified Binja.Core as BN
import qualified Blaze.Import.CallGraph as CG
import Blaze.Import.Cfg (CfgImporter (getCfg))
import Blaze.Import.Source.BinaryNinja (BNImporter (BNImporter))
import Blaze.Types.Import (ImportResult (ImportResult))
import qualified Blaze.UI.Db as Db
import Blaze.UI.Prelude hiding (ignore)
import Blaze.UI.Types
  ( EventLoopCtx (EventLoopCtx)
  , EventLoop
  , runEventLoop
  )
import Blaze.UI.Types.Cfg.Snapshot (emptySnapState)
import Control.Concurrent.STM.TVar (newTVarIO)
import qualified Data.HashMap.Strict as HashMap
import System.Directory (removeFile)
import System.IO.Temp (emptySystemTempFile)
import Test.Hspec



diveBin :: FilePath
diveBin = "res/test_bins/Dive_Logger/Dive_Logger.bndb"

tryRemoveFile :: FilePath -> IO ()
tryRemoveFile p = removeFile p `catch` ignore
  where
    ignore :: SomeException -> IO ()
    ignore _ = return ()

mockEventLoopCtx :: IO EventLoopCtx
mockEventLoopCtx = EventLoopCtx
  <$> newTVarIO HashMap.empty
  <*> newTVarIO HashMap.empty
  <*> newTVarIO emptySnapState
  <*> emptySystemTempFile "blazeTest"

mockEventLoop :: EventLoop a -> IO a
mockEventLoop m = do
  ctx <- mockEventLoopCtx
  Db.init $ ctx ^. #sqliteFilePath
  r <- runEventLoop m ctx
  clean ctx
  return r

clean :: EventLoopCtx -> IO ()
clean = tryRemoveFile . view #sqliteFilePath
  

spec :: Spec
spec = describe "Blaze.UI.Db" $ do
  context "Cfg" $ do
    bv <- runIO $ unsafeFromRight <$> BN.getBinaryView diveBin
    let imp = BNImporter bv
    selectDive <- runIO $ fromJust <$> CG.getFunction imp 0x804e080
    (ImportResult _ originalCfg _) <- runIO $ fromJust <$> getCfg imp selectDive
    cid <- runIO $ randomIO
    mRetrievedCfg <- runIO $ mockEventLoop $ do
      Db.saveCfg cid originalCfg
      Db.getCfg cid

    it "Should save and retrieve a pil cfg" $ do
      mRetrievedCfg `shouldBe` Just originalCfg
