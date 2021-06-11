module Blaze.UI.SnapshotSpec where

import Blaze.UI.Prelude hiding (ignore)
import Data.Time.Clock (UTCTime(UTCTime))
import qualified Blaze.Types.Graph as G
import Blaze.UI.Types.Cfg.Snapshot
import Blaze.UI.Types.Cfg (CfgId(CfgId))
import qualified Blaze.UI.Types.BinaryHash as BinaryHash
import Blaze.Util.Spec (mkUuid1)
import qualified Data.HashMap.Strict as HashMap
import Test.Hspec


utc :: Int -> UTCTime
utc n = UTCTime (toEnum n) (toEnum n)

mkId :: Int -> CfgId
mkId = CfgId . mkUuid1

-- | Used to print out sample encoding, and possibly for future tests
branch1 :: Branch BranchTree
branch1 = Branch
  { hostBinaryPath = "/tmp"
  , bndbHash = BinaryHash.fromByteString "branch1"
  , originFuncAddr = 0
  , originFuncName = "foo"
  , branchName = Nothing
  , rootNode = mkId 0
  , snapshotInfo = HashMap.fromList attrs
  , tree = G.fromEdges
    . fmap (G.fromTupleLEdge . (\(a, b) -> ((), (mkId a, mkId b))))
    $ edges'
  }
  where
    attrs = [ (mkId 0, SnapshotInfo (Just "a") (utc 0) (utc 0) Immutable)
            , (mkId 1, SnapshotInfo (Just "b") (utc 1) (utc 1) Immutable)
            , (mkId 2, SnapshotInfo (Just "c") (utc 2) (utc 2) Immutable)
            , (mkId 3, SnapshotInfo Nothing (utc 3) (utc 3) Autosave)
            , (mkId 4, SnapshotInfo (Just "d") (utc 4) (utc 4) Immutable)
            , (mkId 5, SnapshotInfo Nothing (utc 5) (utc 5) Autosave)
            ]
    edges' = [ (0, 1)
             , (0, 2)
             , (0, 3)
             , (2, 4)
             , (4, 5)
             ]


-- Note: the previous test was eliminated because the Snapshot module
-- was greatly simplified.
spec :: Spec
spec = return ()
