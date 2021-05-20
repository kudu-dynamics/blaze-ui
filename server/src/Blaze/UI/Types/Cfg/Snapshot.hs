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


type Name = Text

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

-- one SnapState per binary (and user? eventually)
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
    , branches :: [Branch BranchTransport]
    }
  deriving (Eq, Ord, Show, Generic)
instance ToJSON OutgoingMsg
instance FromJSON OutgoingMsg


data IncomingMsg
  -- Loads new Cfg based off of parent (CfgId arg)
  -- copies parent CFG as a new working cfg
  -- returns Cfg
  = GetAllBranches

  | GetBranchesOfFunction {originFuncAddr :: Word64}

  | RenameBranch { branchId :: BranchId, name :: Text }

  | LoadSnapshot { branchId :: BranchId, cfgId :: CfgId }

  -- Copies current CFG into snapshot tree (new CfgId)
  -- returns updated snapshot tree
  | SaveSnapshot CfgId (Maybe Name)

  -- renames cfg snapshot
  -- returns updated snapshot tree containing Cfg
  | RenameSnapshot CfgId Name

  deriving (Eq, Ord, Show, Generic)
instance ToJSON IncomingMsg
instance FromJSON IncomingMsg

data SnapshotType
  = AutoSave
  | Immutable
  deriving (Eq, Ord, Show, Generic, Bounded, ToJSON, FromJSON)

data SnapshotInfo = SnapshotInfo
  { name :: Maybe Text
  , date :: UTCTime
  , snapshotType :: SnapshotType
  } deriving (Eq, Ord, Show, Generic, ToJSON, FromJSON)
type BranchTree = AlgaGraph () SnapshotInfo CfgId

type BranchTransport = GraphTransport () SnapshotInfo CfgId

data Branch a = Branch
  { originFuncAddr :: Address
  , branchName :: Maybe Text
  , rootNode :: CfgId
  , tree :: a
  } deriving (Eq, Ord, Show, Generic, FromJSON, ToJSON, Functor, Foldable, Traversable)


