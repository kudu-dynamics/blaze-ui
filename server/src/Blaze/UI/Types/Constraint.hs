module Blaze.UI.Types.Constraint where

import Blaze.Prelude hiding (Symbol)

import Blaze.UI.Types.Cfg (CfgId)
import qualified Blaze.Types.Pil as Pil

data ConstraintError
  = VarNameNotFound Text
  | InvalidOperator Text
  | ParseError Text
  deriving stock (Eq, Ord, Show, Generic)
  deriving anyclass (ToJSON, FromJSON, Hashable)

newtype ServerToBinja
  = SBInvalidConstraint { parseError :: ConstraintError }
  deriving stock (Eq, Ord, Show, Generic)
  deriving anyclass (ToJSON, FromJSON, Hashable)

data BinjaToServer
  = AddConstraint { cfgId :: CfgId
                  , node :: UUID
                  , stmtIndex :: Word64
                  , exprText :: Text
                  }
  deriving stock (Eq, Ord, Show, Generic)
  deriving anyclass (ToJSON, FromJSON, Hashable)


dummyParse :: Text -> Either ConstraintError Pil.Stmt
dummyParse = Right . Pil.Constraint . Pil.ConstraintOp . Pil.Expression 8 . Pil.UNIMPL
