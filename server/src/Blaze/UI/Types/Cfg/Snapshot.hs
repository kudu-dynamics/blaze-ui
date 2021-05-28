module Blaze.UI.Types.Cfg.Snapshot where

import Blaze.Prelude hiding (Symbol)

import qualified Data.HashMap.Strict as HashMap
import System.Random (Random)
import Blaze.Types.Cfg (PilCfg)
import Blaze.UI.Types.Cfg (CfgId)
import Blaze.Types.Graph.Alga (AlgaGraph)
import Data.Time.Clock (UTCTime)
import Control.Concurrent.STM.TMVar (TMVar)
import Database.Selda.SqlType ( Lit(LCustom)
                              , SqlTypeRep(TBlob)
                              , SqlType
                              )
import qualified Database.Selda.SqlType as Sql
import Blaze.UI.Types.Graph (GraphTransport)
import Blaze.UI.Types.BinaryHash (BinaryHash)


newtype BranchId = BranchId UUID
  deriving (Eq, Ord, Show, Generic)
  deriving newtype (Random)
  deriving anyclass (Hashable, ToJSON, FromJSON)

instance SqlType BranchId where
   mkLit (BranchId x) = LCustom TBlob $ Sql.mkLit x
   sqlType _ = TBlob
   fromSql x = BranchId $ Sql.fromSql x
   defaultValue = LCustom TBlob (Sql.defaultValue :: Lit UUID)

-- ACTIVE cfgs are mutable, AUTO saved
data ActiveCfg = ActiveCfg
  { branchId :: BranchId
  , cfg :: TMVar PilCfg
  } deriving (Eq, Generic)

-- one SnapState per binary and user
data SnapState = SnapState
  { branches :: HashMap BranchId (Branch BranchTree)
  -- active cfg's are unsaved/snapped and can be mutated
  , activeCfgs :: HashMap CfgId ActiveCfg
  -- immutable Cfgs
  , savedCfgs :: HashMap CfgId PilCfg
  } deriving (Eq, Generic)

emptySnapState :: SnapState
emptySnapState = SnapState
  { branches = HashMap.empty
  , activeCfgs = HashMap.empty
  , savedCfgs = HashMap.empty
  }

-- Persistence :
-- eventually, store working cfg map and snapshots in db

-- Info maps:
-- CfgId -> Maybe BranchId (nothing means it's an origin)
-- CfgId -> Cfg
-- CfgId -> ActiveCfg

-- Active CFGs map has CfgId -> WorkingCfg
-- ActiveCfg = parentId, branchId

data OutgoingMsg
  = SnapshotBranch
    { branchId :: BranchId
    , branch :: Branch BranchTransport
    }
                     
  | BranchesOfFunction
    { funcAddress :: Word64
    , branches :: [(BranchId, Branch BranchTransport)]
    }
  | BranchesOfBinary
    { branches :: [(BranchId, Branch BranchTransport)] }
  deriving (Eq, Ord, Show, Generic)
instance ToJSON OutgoingMsg
instance FromJSON OutgoingMsg


data IncomingMsg
  = GetAllBranches -- all for binary

  | GetBranchesOfFunction {originFuncAddr :: Word64}

  | RenameBranch { branchId :: BranchId, name :: Text }

  -- loads a cfg snapshot
  -- if not an autosave, it creates one and returns that cfgid
  | LoadSnapshot { branchId :: BranchId, cfgId :: CfgId }

  -- Copies current CFG into snapshot tree (new CfgId)
  -- returns updated snapshot tree
  | SaveSnapshot { cfgId :: CfgId }

  -- renames cfg snapshot
  -- returns updated snapshot tree containing Cfg
  | RenameSnapshot { cfgId :: CfgId, name :: Text }

  deriving (Eq, Ord, Show, Generic)
instance ToJSON IncomingMsg
instance FromJSON IncomingMsg

data SnapshotType
  = Autosave
  | Immutable
  deriving (Eq, Ord, Show, Generic, Bounded, ToJSON, FromJSON)


data SnapshotInfo = SnapshotInfo
  { name :: Maybe Text
  , date :: UTCTime -- creation date
  -- TODO: add modified date for autosave snapshots.
  -- the problem currently is that updating things in the snapshot tree is
  -- expensive because we just store it as a json blob
  -- so I don't want to update the modified date each action
  , snapshotType :: SnapshotType
  } deriving (Eq, Ord, Show, Generic, ToJSON, FromJSON)

type BranchTree = AlgaGraph () SnapshotInfo CfgId

type BranchTransport = GraphTransport () SnapshotInfo CfgId

data Branch a = Branch
  { bndbHash :: BinaryHash
  , originFuncAddr :: Address
  , branchName :: Maybe Text
  , rootNode :: CfgId
  , tree :: a
  } deriving (Eq, Ord, Show, Generic, FromJSON, ToJSON, Functor, Foldable, Traversable)

