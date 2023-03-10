module Blaze.UI.Types.Poi where

import Blaze.Prelude hiding (Symbol)

import System.Random (Random)
import Data.Time.Clock (UTCTime)
import Data.Time.Compat ()
import Database.Selda (SqlRow, Table, primary, Attr((:-)), table)
import Database.Selda.SqlType ( Lit(LCustom)
                              , SqlTypeRep(TBlob)
                              , SqlType
                              )
import qualified Database.Selda.SqlType as Sql
import Blaze.UI.Types.HostBinaryPath (HostBinaryPath)
import Blaze.UI.Types.Session (ClientId)
import Blaze.UI.Types.Db.Address ()
import Blaze.UI.Types.Cfg (CfgId)
import Blaze.UI.Types.BinaryHash (BinaryHash)


newtype PoiId = PoiId UUID
  deriving (Eq, Ord, Show, Generic)
  deriving newtype (Random)
  deriving anyclass (Hashable, ToJSON, FromJSON)

instance SqlType PoiId where
   mkLit (PoiId x) = LCustom TBlob $ Sql.mkLit x
   sqlType _ = TBlob
   fromSql x = PoiId $ Sql.fromSql x
   defaultValue = LCustom TBlob (Sql.defaultValue :: Lit UUID)

data ServerToBinja
  = PoisOfBinary { pois :: [Poi] }
  | GlobalPoisOfBinary { globalPois :: [Poi] }
  deriving (Eq, Ord, Show, Generic)
  deriving anyclass (ToJSON, FromJSON, Hashable)

data BinjaToServer
  = GetPoisOfBinary
  
  | AddPoi { funcAddr :: Address
           , instrAddr :: Address
           , name :: Maybe Text
           , description :: Maybe Text
           }

  | DeletePoi { poiId :: PoiId }

  | RenamePoi { poiId :: PoiId
              , name :: Maybe Text
              }

  | DescribePoi { poiId :: PoiId
                , description :: Maybe Text
                }

  | ActivatePoiSearch { poiId :: PoiId
                      , activeCfg :: Maybe CfgId
                      }

  | DeactivatePoiSearch { activeCfg :: Maybe CfgId }

  deriving (Eq, Ord, Show, Generic, ToJSON, FromJSON, Hashable)


data Poi = Poi
  { poiId :: PoiId
  , clientId :: Maybe ClientId
  , hostBinaryPath :: Maybe HostBinaryPath
  , binaryHash :: BinaryHash
  , created :: UTCTime
  , funcAddr :: Address
  , instrAddr :: Address
  , name :: Maybe Text
  , description :: Maybe Text
  , isGlobalPoi :: Bool
  } deriving (Eq, Ord, Show, Generic, ToJSON, FromJSON, Hashable, SqlRow)

poiTable :: Table Poi
poiTable = table "poi" [#poiId :- primary]
