module Blaze.UI.SnapshotSpec where

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
import Data.Time.Clock (UTCTime(UTCTime))
import qualified Blaze.Types.Graph as G
import Blaze.UI.Types.Cfg.Snapshot
import Blaze.UI.Cfg.Snapshot
import Blaze.UI.Types.Cfg (CfgId(CfgId))
import Blaze.Util.Spec (mkUuid1)
import Test.Hspec

utc :: Int -> UTCTime
utc n = UTCTime (toEnum n) (toEnum n)

mkId :: Int -> CfgId
mkId = CfgId . mkUuid1

branch1 :: Branch BranchTree
branch1 = Branch
  { originFuncAddr = 0
  , branchName = Nothing
  , rootNode = mkId 0
  , tree = G.addNodesWithAttrs nodes'
    .  G.fromEdges
    . fmap G.fromTupleLEdge
    . fmap (\(a, b) -> ((), (mkId a, mkId b)))
    $ edges'
  }
  where
    nodes' = [ (mkId 0, SnapshotInfo (Just "a") (utc 0) Immutable)
             , (mkId 1, SnapshotInfo (Just "b") (utc 1) Immutable)
             , (mkId 2, SnapshotInfo (Just "c") (utc 2) Immutable)
             , (mkId 3, SnapshotInfo Nothing (utc 3) AutoSave)
             , (mkId 4, SnapshotInfo (Just "d") (utc 4) Immutable)
             , (mkId 5, SnapshotInfo Nothing (utc 5) AutoSave)
             ]
    edges' = [ (0, 1)
             , (0, 2)
             , (0, 3)
             , (2, 4)
             , (4, 5)
             ]



spec :: Spec
spec = describe "Blaze.UI.Snapshot" $ do
  context "Snapshot" $ do

    it "Should do something" $ do
      False `shouldBe` True
