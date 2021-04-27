module Blaze.UI.Types.Cfg.Snapshot where

import Blaze.Prelude hiding (Symbol)

import Blaze.Types.Pil (Stmt)
import Blaze.Types.Cfg ( CfNode, CfEdge, Cfg )
import qualified Blaze.Graph as G
import qualified Data.HashMap.Strict as HMap
import Blaze.Pretty (pretty)
import Blaze.Cfg.Interprocedural (
  InterCfg,
  unInterCfg,
 )
import System.Random (Random)
import qualified Blaze.Types.Cfg as Cfg
import Blaze.Types.Cfg (PilCfg)
import Blaze.Function (Function)
import Blaze.UI.Types.Cfg (CfgId)
import Blaze.Types.Graph (Graph)
import qualified Blaze.Types.Graph as G
import Blaze.Types.Graph.Alga (AlgaGraph)
import Data.Time.Clock (UTCTime)
import Control.Concurrent.STM.TVar (TVar)
import Control.Concurrent.STM.TMVar (TMVar, takeTMVar, putTMVar)

type Name = Text

newtype BranchId = BranchId UUID
  deriving (Eq, Ord, Show, Generic)
  deriving newtype (Random)
  deriving anyclass (Hashable, ToJSON, FromJSON)

newtype ActiveCfgId = ActiveCfgId CfgId
  deriving (Eq, Ord, Show, Generic)
  deriving newtype (Random)
  deriving anyclass (Hashable, ToJSON, FromJSON)

newtype SavedCfgId = SavedCfgId CfgId
  deriving (Eq, Ord, Show, Generic)
  deriving newtype (Random)
  deriving anyclass (Hashable, ToJSON, FromJSON)


-- ACTIVE cfgs are mutable, AUTO saved
data ActiveCfg = ActiveCfg
  { branchId :: BranchId
  , cfg :: TMVar PilCfg
  } deriving (Eq, Generic)

-- one SnapState per binary (and user? eventually)
data SnapState = SnapState
  { branches :: HashMap BranchId SnapshotBranch
  -- active cfg's are unsaved/snapped and can be mutated
  , activeCfgs :: HashMap ActiveCfgId ActiveCfg
  -- immutable Cfgs
  , savedCfgs :: HashMap SavedCfgId PilCfg
  } deriving (Eq, Generic)

-- Persistence :
-- eventually, store working cfg map and snapshots in db

-- Info maps:
-- CfgId -> Maybe BranchId (nothing means it's an origin)
-- CfgId -> Cfg
-- CfgId -> ActiveCfg

-- Active CFGs map has CfgId -> WorkingCfg
-- ActiveCfg = parentId, branchId

data SnapshotMsg
  -- Create new Cfg
  -- store cfg as new origin snapshot
  -- returns Cfg with name/date
  = New { startFuncAddress :: Word64 }

  -- Loads new Cfg based off of parent (CfgId arg)
  -- copies parent CFG as a new working cfg
  -- returns Cfg
  | Load CfgId

  -- Copies current CFG into snapshot tree (new CfgId)
  -- returns updated snapshot tree
  | Save CfgId (Maybe Name)

  -- renames cfg snapshot
  -- returns updated snapshot tree
  | Rename CfgId Name
  deriving (Eq, Ord, Show, Generic)
instance ToJSON SnapshotMsg
instance FromJSON SnapshotMsg



data SnapshotInfo = SnapshotInfo
  { name :: Name
  , date :: UTCTime
  } deriving (Eq, Ord, Show, Generic)

-- data ActiveNode = ActiveNode
--   { activeId :: CfgId -- points to mutable cfg in active map
--   , parentId :: CfgId -- points to immutable snapshot in branch
--   } deriving (Eq, Ord, Show, Generic)

data SnapshotBranch = SnapshotBranch
  { originNode :: SavedCfgId
  , originFunc :: Function
  , activeParentMap :: HashMap ActiveCfgId SavedCfgId -- activeId -> parentId
  , tree :: AlgaGraph () SnapshotInfo SavedCfgId
  } deriving (Eq, Show, Generic)
  
  
  
  

