{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TemplateHaskell #-}

module Blaze.UI.Types.WebMessages where

import Blaze.Prelude hiding (Symbol)

import qualified Language.PureScript.Bridge as PB
import qualified Language.PureScript.Bridge.PSTypes as PB
import qualified Language.PureScript.Bridge.CodeGenSwitches as S
import Language.PureScript.Bridge.TypeParameters (A)
import Language.PureScript.Bridge ((^==))
import System.Directory (removeDirectoryRecursive)
import Data.BinaryAnalysis as BA
import qualified Blaze.Types.CallGraph as CG
import qualified Blaze.Types.Pil as Pil
import qualified Blaze.UI.Web.Pil as WebPil
import qualified Blaze.Types.Pil.Checker as Ch

-------------------
-- data BadBoy = BadBoy { one :: Int, two :: Text }
--   deriving (Eq, Ord, Show, Generic)

-- instance ToJSON BadBoy
-- instance FromJSON BadBoy

-- data MMaybe a = MJust a
--               | MNothing
--   deriving (Eq, Ord, Show, Generic)

-- instance ToJSON a => ToJSON (MMaybe a)
-- instance FromJSON a => FromJSON (MMaybe a)

-- data MOk a = MOk a
--   deriving (Eq, Ord, Show, Generic)

-- instance ToJSON a => ToJSON (MOk a)
-- instance FromJSON a => FromJSON (MOk a)


data WebToServer = WSTextMessage Text
                 | WSGetFunctionsList
                 | WSGetTypeReport CG.Function
                 | WSNoop
                 deriving (Eq, Ord, Show, Generic)

instance ToJSON WebToServer
instance FromJSON WebToServer


data ServerToWeb = SWTextMessage Text
                 | SWLogInfo Text
                 | SWLogWarn Text
                 | SWLogError Text
                 | SWPilType (WebPil.PilType Int)
                 | SWNoop
                 | SWFunctionsList [CG.Function]

                 -- TODO: make a real type report
                 | SWFunctionTypeReport Text
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
  , mkT (Proxy :: Proxy CG.CallDest)


  -- Types from Blaze.Pil
  , mkT (Proxy :: Proxy (Pil.Statement A))
  , mkT (Proxy :: Proxy (Pil.DefOp A))
  , mkT (Proxy :: Proxy (Pil.ConstraintOp A))
  , mkT (Proxy :: Proxy (Pil.StoreOp A))
  , mkT (Proxy :: Proxy (Pil.UnimplMemOp A))
  , mkT (Proxy :: Proxy (Pil.EnterContextOp A))
  , mkT (Proxy :: Proxy (Pil.ExitContextOp A))
  , mkT (Proxy :: Proxy (Pil.CallOp A))
  , mkT (Proxy :: Proxy (Pil.DefPhiOp A))

  , mkT (Proxy :: Proxy (Pil.CallDest A))
  , mkT (Proxy :: Proxy (Pil.ConstPtrOp A))
  
  , mkT (Proxy :: Proxy (Pil.CtxIndex))
  , mkT (Proxy :: Proxy (Pil.Ctx))
  , mkT (Proxy :: Proxy (Pil.PilVar))


  -- types from Web.Pil
  , mkT (Proxy :: Proxy (WebPil.PilType A))
  , mkT (Proxy :: Proxy (WebPil.TIntOp A))
  , mkT (Proxy :: Proxy (WebPil.TFloatOp A))
  , mkT (Proxy :: Proxy (WebPil.TBitVectorOp A))
  , mkT (Proxy :: Proxy (WebPil.TPointerOp A))
  , mkT (Proxy :: Proxy (WebPil.TArrayOp A))
  , mkT (Proxy :: Proxy (WebPil.TFunctionOp A))


  , mkT (Proxy :: Proxy (WebPil.Sym))
  , mkT (Proxy :: Proxy (WebPil.TypeError))
  , mkT (Proxy :: Proxy (WebPil.TypeReport))
  , mkT (Proxy :: Proxy (WebPil.TypedExpr))

  
  -- , mkT (Proxy :: Proxy BadBoy)
  -- , mkT (Proxy :: Proxy (MMaybe A))
  -- , mkT (Proxy :: Proxy (MOk A))

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
