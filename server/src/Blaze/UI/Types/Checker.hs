
module Blaze.UI.Types.Checker where

import Blaze.Prelude hiding (Symbol)

import Data.Hashable.Time ()
import Database.Selda (SqlRow, Table, primary, Attr((:-)), table)
import Blaze.UI.Types.Db (Blob)
import Blaze.UI.Types.Db.Address ()
import Blaze.UI.Types.Cfg (CfgId)
import Blaze.Types.Pil (
  PilVar,
  Statement,
 )
import Blaze.Types.Pil.Checker ( InfoExpression
                               , PilType
                               , DeepSymType
                               , Sym
                               , UnifyConstraintsError
                               , SymInfo
                               )


data ServerToBinja
  = TypesForCfg { cfgId :: CfgId, varTypes :: HashMap PilVar DeepSymType }
  | TypeForVar { cfgId :: CfgId, var :: PilVar, varType :: DeepSymType }
  deriving (Eq, Ord, Show, Generic)
  deriving anyclass (ToJSON, FromJSON, Hashable)

data BinjaToServer
  = GetTypesForCfg { cfgId :: CfgId }
  | GetTypesForVar { cfgId :: CfgId, var :: PilVar }
  deriving (Eq, Ord, Show, Generic, ToJSON, FromJSON, Hashable)

data TypeReport = TypeReport
  { symTypeStmts :: [(Int, Statement (InfoExpression (SymInfo, Maybe DeepSymType)))]
  -- , symStmts :: [(Int, Statement SymExpression)]
  , varSymTypeMap :: HashMap PilVar DeepSymType
  , varSymMap :: HashMap PilVar Sym
  -- , varEqMap :: VarEqMap
  -- , funcSymTypeMap :: HashMap (FuncVar SymExpression) DeepSymType
  -- , funcSymMap :: HashMap (FuncVar SymExpression) Sym
  , errors :: [UnifyConstraintsError DeepSymType]
  , flatSolutions :: HashMap Sym (PilType Sym)
  -- , solutions :: HashMap Sym DeepSymType
  , originMap :: HashMap Sym Sym -- from UnifyState
  -- , errorConstraints :: HashMap Sym [Constraint] -- original constraints
  -- , ogConstraints :: [Constraint]
  } deriving (Eq, Ord, Show, Generic, Hashable, ToJSON, FromJSON)

data CfgTypeReport = CfgTypeReport
  { cfgId :: CfgId
  , typeReport :: Blob TypeReport
  } deriving (Eq, Ord, Show, Generic, SqlRow)

poiTable :: Table CfgTypeReport
poiTable = table "typeReport" [#cfgId :- primary]

