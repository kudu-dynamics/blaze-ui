module Blaze.UI.Types.Cfg.Snapshot where

import Blaze.Prelude hiding (Symbol)

import System.Random (Random)
import Blaze.UI.Types.Cfg (CfgId)
import Blaze.Types.Graph.Alga (AlgaGraph)
import Data.Time.Clock (UTCTime)
import Database.Selda.SqlType ( Lit(LCustom)
                              , SqlTypeRep(TBlob)
                              , SqlType
                              )
import qualified Database.Selda.SqlType as Sql
import Blaze.UI.Types.Graph (GraphTransport)
import Blaze.UI.Types.BndbHash (BndbHash)
import Blaze.UI.Types.HostBinaryPath (HostBinaryPath)
import Data.Time.Compat ()

newtype BranchId = BranchId UUID
  deriving (Eq, Ord, Show, Generic)
  deriving newtype (Random)
  deriving anyclass (Hashable, ToJSON, FromJSON)

instance SqlType BranchId where
   mkLit (BranchId x) = LCustom TBlob $ Sql.mkLit x
   sqlType _ = TBlob
   fromSql x = BranchId $ Sql.fromSql x
   defaultValue = LCustom TBlob (Sql.defaultValue :: Lit UUID)

data ServerToBinja
  = SnapshotBranch
    { branchId :: BranchId
    , branch :: Branch BranchTransport
    }
                     
  | BranchesOfFunction
    { funcAddress :: Word64
    , branches :: [(BranchId, Branch BranchTransport)]
    }
  | BranchesOfBinary
    { hostBinaryPath :: HostBinaryPath
    , branches :: [(BranchId, Branch BranchTransport)]
    }
  | BranchesOfClient
    { branchesOfClient :: [(HostBinaryPath, [(BranchId, Branch BranchTransport)])] }

  | DeleteSnapshotConfirmationRequest
    { snapshotRequestedForDeletion :: CfgId
    , deletedNodes :: [CfgId]
    , willWholeBranchBeDeleted :: Bool
    }
  deriving (Eq, Ord, Show, Generic, ToJSON, FromJSON, Hashable)


data BinjaToServer
  = GetAllBranchesOfClient
  
  | GetAllBranchesOfBinary -- all for currently focused binary

  | GetBranchesOfFunction {originFuncAddr :: Word64}

  | RenameBranch { branchId :: BranchId, name :: Text }

  -- loads a cfg snapshot
  -- if not an autosave, it creates one and returns that cfgid
  | LoadSnapshot { cfgId :: CfgId }

  -- Copies current CFG into snapshot tree (new CfgId)
  -- returns updated snapshot tree
  | SaveSnapshot { cfgId :: CfgId }

  -- renames cfg snapshot
  -- returns updated snapshot tree containing Cfg
  | RenameSnapshot { cfgId :: CfgId, name :: Text }

  -- Copies current CFG into snapshot tree (new CfgId)
  -- returns updated snapshot tree
  | PreviewDeleteSnapshot { cfgId :: CfgId }
  | ConfirmDeleteSnapshot { cfgId :: CfgId }
  
  deriving (Eq, Ord, Show, Generic, ToJSON, FromJSON)


data SnapshotType
  = Autosave
  | Immutable
  deriving (Eq, Ord, Read, Show, Generic, Enum, Bounded, ToJSON, FromJSON, Hashable, SqlType)


data SnapshotInfo = SnapshotInfo
  { name :: Maybe Text
  , created :: UTCTime
  , modified :: UTCTime
  , snapshotType :: SnapshotType
  } deriving (Eq, Ord, Show, Generic, ToJSON, FromJSON, Hashable)

type BranchTree = AlgaGraph () CfgId CfgId

type BranchTransport = GraphTransport () CfgId

data Branch a = Branch
  { hostBinaryPath :: HostBinaryPath
  , bndbHash :: BndbHash
  , originFuncAddr :: Address
  , originFuncName :: Text
  , branchName :: Maybe Text
  , rootNode :: CfgId
  , snapshotInfo :: HashMap CfgId SnapshotInfo
  , tree :: a
  } deriving (Eq, Ord, Show, Generic, FromJSON, ToJSON,Hashable, Functor, Foldable, Traversable)

