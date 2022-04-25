module Blaze.UI.DbSpec where

import qualified Binja.Core as BN
import qualified Blaze.Import.CallGraph as CG
import Blaze.Import.Cfg (CfgImporter (getCfg))
import Blaze.Import.Source.BinaryNinja (BNImporter (BNImporter))
import Blaze.Types.Import (ImportResult (ImportResult))
import qualified Blaze.UI.Types.Cfg.Snapshot as Snapshot
import qualified Blaze.UI.Db as Db
import Blaze.UI.Prelude hiding (ignore)
import Blaze.UI.Types
  ( SessionState (SessionState)
  , EventLoop
  , runEventLoop
  )
import qualified Data.HashMap.Strict as HashMap
import System.Directory (removeFile)
import System.IO.Temp (emptySystemTempFile)
import qualified Blaze.UI.Types.CachedCalc as CC
import Blaze.Types.Graph as G
import qualified Data.HashSet as HashSet
import Blaze.Util.Spec (mkUuid1)
import qualified Blaze.UI.Types.BinaryManager as BM
import Blaze.UI.Types.Session (ClientId(ClientId))
import Test.Hspec
import qualified Data.UUID as UUID
import qualified Data.Text as Text
import qualified Blaze.UI.Types.BinaryHash as BinaryHash
import qualified Blaze.Types.Cfg.Grouping as GCfg

diveBin :: FilePath
diveBin = "res/test_bins/Dive_Logger/Dive_Logger.bndb"

tryRemoveFile :: FilePath -> IO ()
tryRemoveFile p = removeFile p `catch` ignore
  where
    ignore :: SomeException -> IO ()
    ignore _ = return ()

mockSessionState :: Db.Conn -> IO SessionState
mockSessionState conn = SessionState cid hpath bhash
  <$> atomically (BM.create bmdir cid hpath)
  <*> newTVarIO HashMap.empty
  <*> newTVarIO HashMap.empty
  <*> newEmptyTMVarIO
  <*> newTVarIO HashSet.empty
  <*> newTQueueIO
  <*> pure conn
  <*> newTVarIO Nothing
  <*> atomically CC.create
  where
    bmdir = "/tmp/blaze/bm"
    hpath = "/tmp/blaze/spec"
    bhash = BinaryHash.fromByteString "mockHash"
    cid = ClientId . Text.append "testuser_" . UUID.toText $ mkUuid1 (0 :: Int)

mockEventLoop :: EventLoop a -> IO a
mockEventLoop m = do
  dbFile <- emptySystemTempFile "blazeTest"
  conn <- Db.init dbFile
  ctx' <- mockSessionState conn
  (Right r) <- runEventLoop m ctx'
  tryRemoveFile dbFile
  return r 

spec :: Spec
spec = describe "Blaze.UI.Db" $ do
  context "Cfg" $ do
    bid <- runIO randomIO
    cid <- runIO randomIO
    bv <- runIO $ unsafeFromRight <$> BN.getBinaryView diveBin
    runIO $ BN.updateAnalysisAndWait bv
    let imp = BNImporter bv
    selectDive <- runIO $ fromJust <$> CG.getFunction imp 0x804e080
    (ImportResult _ originalCfg _) <- runIO $ fromJust <$> getCfg imp selectDive 0
    let originalCfg' = GCfg.foldGroups originalCfg []
    mRetrievedCfg <- runIO . mockEventLoop $ do
      Db.saveNewCfg_ bid cid originalCfg' Snapshot.Immutable
      Db.getCfg cid

    it "Should save and retrieve a pil cfg" $ do
      mRetrievedCfg `shouldBe` Just originalCfg'

    mRetrievedCfg2 <- runIO . mockEventLoop $ do
      let firstCfg = G.removeEdges
            (fmap (\(GCfg.CfEdge src' dst' _) -> G.Edge src' dst')
               . HashSet.toList
               . GCfg.succEdges (originalCfg' ^. #root)
               $ originalCfg')
            originalCfg'
      Db.saveNewCfg_ bid cid firstCfg Snapshot.Immutable
      Db.setCfg cid originalCfg'
      Db.getCfg cid

    it "Should overwrite first cfg using setCfg" $ do
      mRetrievedCfg2 `shouldBe` Just originalCfg'
