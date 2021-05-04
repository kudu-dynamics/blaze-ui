module Blaze.UI.Types.Cfg.Snapshot where

import Blaze.Prelude hiding (Symbol)

import Blaze.Types.Pil (Stmt)
import Blaze.Types.Cfg ( CfNode, CfEdge, Cfg )
import qualified Blaze.Graph as G
import Blaze.Graph (Graph)
import qualified Data.Set as Set
import qualified Data.HashMap.Strict as HashMap
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
import Database.Selda.SqlType ( Lit(LCustom)
                              , SqlTypeRep(TBlob)
                              , SqlType
                              )
import qualified Database.Selda.SqlType as Sql


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


-- newtype ActiveCfgId = ActiveCfgId CfgId
--   deriving (Eq, Ord, Show, Generic)
--   deriving newtype (Random)
--   deriving anyclass (Hashable, ToJSON, FromJSON)

-- newtype SavedCfgId = SavedCfgId CfgId
--   deriving (Eq, Ord, Show, Generic)
--   deriving newtype (Random)
--   deriving anyclass (Hashable, ToJSON, FromJSON)


-- ACTIVE cfgs are mutable, AUTO saved
data ActiveCfg = ActiveCfg
  { branchId :: BranchId
  , cfg :: TMVar PilCfg
  } deriving (Eq, Generic)

-- one SnapState per binary (and user? eventually)
data SnapState = SnapState
  { branches :: HashMap BranchId Branch
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

data Branch = Branch
  { originFunc :: Function
  , rootNode :: CfgId
  , tree :: BranchTree
  } deriving (Eq, Show, Generic)


