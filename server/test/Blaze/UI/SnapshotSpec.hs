module Blaze.UI.SnapshotSpec where

import Blaze.UI.Prelude hiding (ignore)
import Data.Time.Clock (UTCTime(UTCTime))
import qualified Blaze.Types.Graph as G
import Blaze.UI.Types.Cfg.Snapshot
import Blaze.UI.Cfg.Snapshot
import Blaze.UI.Types.Cfg (CfgId(CfgId))
import qualified Blaze.UI.Types.BinaryHash as BinaryHash
import Blaze.Util.Spec (mkUuid1)
import Test.Hspec

utc :: Int -> UTCTime
utc n = UTCTime (toEnum n) (toEnum n)

mkId :: Int -> CfgId
mkId = CfgId . mkUuid1

mkBranchTree :: [(Int, SnapshotInfo)] -> [(Int, Int)] -> BranchTree
mkBranchTree nodes' edges'
  = G.addNodesWithAttrs (over _1 mkId <$> nodes')
  .  G.fromEdges
  . fmap G.fromTupleLEdge
  . fmap (\(a, b) -> ((), (mkId a, mkId b)))
  $ edges'

branchTree0 :: BranchTree
branchTree0 = mkBranchTree nodes' edges'
  where
    nodes' = [(0, SnapshotInfo (Just "a") (utc 0) Autosave)]
    edges' = []


branch1 :: Branch BranchTree
branch1 = Branch
  { hostBinaryPath = "/tmp"
  , bndbHash = BinaryHash.fromByteString "branch1"
  , originFuncAddr = 0
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
             , (mkId 3, SnapshotInfo Nothing (utc 3) Autosave)
             , (mkId 4, SnapshotInfo (Just "d") (utc 4) Immutable)
             , (mkId 5, SnapshotInfo Nothing (utc 5) Autosave)
             ]
    edges' = [ (0, 1)
             , (0, 2)
             , (0, 3)
             , (2, 4)
             , (4, 5)
             ]



spec :: Spec
spec = describe "Blaze.UI.Snapshot" $ do
  context "immortalizeAutosave" $ do
    it "should create new node and make old node immutable fortree with single node" $ do
      let oldCid = mkId 0
          newCid = mkId 1
          saveTime = utc 1
          result = immortalizeAutosave oldCid newCid saveTime branchTree0
          expected = mkBranchTree
            [ (0, SnapshotInfo (Just "a") (utc 0) Immutable)
            , (1, SnapshotInfo Nothing saveTime Autosave)
            ]
            [(0, 1)]
      
      result `shouldBe` expected
