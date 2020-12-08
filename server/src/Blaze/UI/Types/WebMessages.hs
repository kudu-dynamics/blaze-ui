{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TemplateHaskell #-}

module Blaze.UI.Types.WebMessages where

import Blaze.Prelude hiding (Symbol)

import qualified Language.PureScript.Bridge as PB
import qualified Language.PureScript.Bridge.PSTypes as PB
import qualified Language.PureScript.Bridge.CodeGenSwitches as S
import Language.PureScript.Bridge ((^==))
import System.Directory (removeDirectoryRecursive)
import Data.BinaryAnalysis as BA
import qualified Blaze.Types.CallGraph as CG

-- -- Going to try not to use external types, except from BinaryAnalysis

-- data Function
--   = Function
--       { _name :: Text
--       , _address :: Address
--       }
--   deriving (Eq, Ord, Show, Generic, FromJSON, ToJSON)

-- instance Hashable Function

-- $(makeFields ''Function)


-------------------

data WebToServer = WSTextMessage { message :: Text }
                 | WSGetFunctionsList
                 | WSNoop
                 deriving (Eq, Ord, Show, Generic)

instance ToJSON WebToServer
instance FromJSON WebToServer


data ServerToWeb = SWTextMessage { message :: Text }
                 | SWLogInfo { message :: Text }
                 | SWLogWarn { message :: Text }
                 | SWLogError { message :: Text }
                 | SWNoop
                 | SWFunctionsList { functions :: [CG.Function] }
                 deriving (Eq, Ord, Show, Generic, ToJSON, FromJSON)


-------------------------
--- Purescript-Bridge

myTypes :: [PB.SumType 'PB.Haskell]
myTypes =
  -- Types from Data.BinaryAnalysis
  [ mkT (Proxy :: Proxy Bytes)
  , mkT (Proxy :: Proxy Bits)
  , mkT (Proxy :: Proxy ByteOffset)
  , mkT (Proxy :: Proxy BitOffset)
  , mkT (Proxy :: Proxy AddressWidth)
  , mkT (Proxy :: Proxy Address)
  , mkT (Proxy :: Proxy BA.Symbol)

  -- Types from Blaze.CallGraph
  , mkT (Proxy :: Proxy CG.Function)


  -- types from here
  , mkT (Proxy :: Proxy ServerToWeb)
  , mkT (Proxy :: Proxy WebToServer)  
  ]
  where
    mkT :: forall t.
             ( Typeable t
             , Generic t
             , PB.GDataConstructor (Rep t)
             , Ord t
             )
          => Proxy t -> PB.SumType 'PB.Haskell
    mkT p = PB.genericShow p . PB.order p $ PB.mkSumType p

psWord64 :: PB.PSType
psWord64 = PB.TypeInfo
  { _typePackage = "purescript-word" -- deprecated?
  , _typeModule = "Data.Word"
  , _typeName = "Word64"
  , _typeParameters = []
  }

psBigInt :: PB.PSType
psBigInt = PB.TypeInfo
  { _typePackage = "purescript-bigints" 
  , _typeModule = "Data.BigInt"
  , _typeName = "BigInt"
  , _typeParameters = []
  }

-- shouldn't really be `Int` because there might be overflow
word64Bridge :: PB.BridgePart
word64Bridge = PB.typeName ^== "Word64" >> return PB.psInt

int64Bridge :: PB.BridgePart
int64Bridge = PB.typeName ^== "Int64" >> return PB.psInt

genPB :: IO ()
genPB = do
  let dir = "../web/gen"
  removeDirectoryRecursive dir
  let s = S.useGenRep <> S.genForeign (S.ForeignOptions True) <> S.genLenses
  PB.writePSTypesWith s dir (PB.buildBridge bridge) myTypes
  where
    bridge = PB.defaultBridge
         <|> word64Bridge
         <|> int64Bridge
