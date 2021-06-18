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
import qualified Data.HashMap.Strict as HashMap
import System.Directory (removeFile)
import System.IO.Temp (emptySystemTempFile)
import Blaze.Types.Cfg as Cfg
import qualified Data.Set as Set
import Blaze.Util.Spec (mkUuid1)
import qualified Blaze.UI.Types.BinaryManager as BM
import Blaze.UI.Types.Session (ClientId(ClientId))
import Test.Hspec
import qualified Data.UUID as UUID
import qualified Data.Text as Text


diveBin :: FilePath
diveBin = "res/test_bins/Dive_Logger/Dive_Logger.bndb"

tryRemoveFile :: FilePath -> IO ()
tryRemoveFile p = removeFile p `catch` ignore
  where
    ignore :: SomeException -> IO ()
    ignore _ = return ()

mockEventLoopCtx :: IO EventLoopCtx
mockEventLoopCtx = EventLoopCtx cid hpath
  <$> atomically (BM.create bmdir cid hpath)
  <*> newTVarIO HashMap.empty
  <*> newTVarIO HashMap.empty
  <*> emptySystemTempFile "blazeTest"
  where
    bmdir = "/tmp/blaze/bm"
    hpath = "/tmp/blaze/spec"
    cid = ClientId . Text.append "testuser_" . UUID.toText $ mkUuid1 (0 :: Int)

mockEventLoop :: EventLoop a -> IO a
mockEventLoop m = do
  ctx' <- mockEventLoopCtx
  Db.init $ ctx' ^. #sqliteFilePath
  (Right r) <- runEventLoop m ctx'
  clean ctx'
  return r

clean :: EventLoopCtx -> IO ()
clean = tryRemoveFile . view #sqliteFilePath
  

spec :: Spec
spec = describe "Blaze.UI.Db" $ do
  context "Cfg" $ do
    bid <- runIO randomIO
    cid <- runIO randomIO
    bv <- runIO $ unsafeFromRight <$> BN.getBinaryView diveBin
    let imp = BNImporter bv
    selectDive <- runIO $ fromJust <$> CG.getFunction imp 0x804e080
    (ImportResult _ originalCfg _) <- runIO $ fromJust <$> getCfg imp selectDive
    mRetrievedCfg <- runIO . mockEventLoop $ do
      Db.saveNewCfg_ bid cid originalCfg
      Db.getCfg cid

    it "Should save and retrieve a pil cfg" $ do
      mRetrievedCfg `shouldBe` Just originalCfg

    mRetrievedCfg2 <- runIO . mockEventLoop $ do
      let firstCfg = Cfg.removeEdges
            (Set.toList $ Cfg.succEdges (originalCfg ^. #root) originalCfg)
            originalCfg
      Db.saveNewCfg_ bid cid firstCfg
      Db.setCfg cid originalCfg
      Db.getCfg cid

    it "Should overwrite first cfg using setCfg" $ do
      mRetrievedCfg2 `shouldBe` Just originalCfg
