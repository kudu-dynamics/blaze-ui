module Blaze.UI.Types.Constraint where

import Blaze.Prelude hiding (Symbol)

import Blaze.UI.Types.Cfg (CfgId)
import qualified Blaze.Types.Pil as Pil

data ConstraintError
  = VarNameNotFound Text
  | InvalidOperator Text
  deriving (Eq, Ord, Show, Generic, ToJSON, FromJSON)

newtype ServerToBinja
  = SBInvalidConstraint { parseError :: ConstraintError }
  deriving (Eq, Ord, Show, Generic)
  deriving anyclass (ToJSON, FromJSON)

data BinjaToServer
  = AddConstraint { cfgId :: CfgId
                  , node :: UUID
                  , stmtIndex :: Word64
                  , exprText :: Text
                  }
  deriving (Eq, Ord, Show, Generic, ToJSON, FromJSON)


dummyParse :: Text -> Either ConstraintError Pil.Stmt
dummyParse = Right . Pil.Constraint . Pil.ConstraintOp . Pil.Expression 8 . Pil.UNIMPL
