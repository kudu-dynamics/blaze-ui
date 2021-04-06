{-# LANGUAGE DataKinds #-}

module Blaze.UI.Types.WebMessages where

import Blaze.Prelude hiding (Symbol)

import qualified Language.PureScript.Bridge as PB
import qualified Language.PureScript.Bridge.CodeGenSwitches as S
import Language.PureScript.Bridge.TypeParameters (A)
import Language.PureScript.Bridge ((^==))
import System.Directory (removeDirectoryRecursive)
import Data.BinaryAnalysis as BA
import qualified Blaze.Types.Function as Blaze
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
                 | WSGetTypeReport Blaze.Function
                 | WSNoop
                 deriving (Eq, Ord, Show, Generic)

instance ToJSON WebToServer
instance FromJSON WebToServer


data ServerToWeb = SWTextMessage Text
                 | SWLogInfo Text
                 | SWLogWarn Text
                 | SWLogError Text
                 | SWPilType WebPil.DeepSymType
                 | SWProblemType [(Int, Pil.Statement Ch.SymExpression)]
                 | SWNoop
                 | SWFunctionsList [Blaze.Function]

                 -- TODO: make a real type report
                 | SWFunctionTypeReport WebPil.TypeReport
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
  , mkT (Proxy :: Proxy Blaze.Function)
  , mkT (Proxy :: Proxy (Pil.CallDest A))


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
  
  , mkT (Proxy :: Proxy Pil.CtxId)
  , mkT (Proxy :: Proxy Pil.Ctx)
  , mkT (Proxy :: Proxy Pil.PilVar)

  -- expressions
  , mkT (Proxy :: Proxy (Pil.ExprOp A))

  , mkT (Proxy :: Proxy (Pil.AdcOp A))
  , mkT (Proxy :: Proxy (Pil.AddOp A))
  , mkT (Proxy :: Proxy (Pil.AddOverflowOp A))
  , mkT (Proxy :: Proxy (Pil.AndOp A))
  , mkT (Proxy :: Proxy (Pil.AsrOp A))
  , mkT (Proxy :: Proxy (Pil.BoolToIntOp A))
  , mkT (Proxy :: Proxy (Pil.CeilOp A))
  , mkT (Proxy :: Proxy (Pil.CmpEOp A))
  , mkT (Proxy :: Proxy (Pil.CmpNeOp A))
  , mkT (Proxy :: Proxy (Pil.CmpSgeOp A))
  , mkT (Proxy :: Proxy (Pil.CmpSgtOp A))
  , mkT (Proxy :: Proxy (Pil.CmpSleOp A))
  , mkT (Proxy :: Proxy (Pil.CmpSltOp A))
  , mkT (Proxy :: Proxy (Pil.CmpUgeOp A))
  , mkT (Proxy :: Proxy (Pil.CmpUgtOp A))
  , mkT (Proxy :: Proxy (Pil.CmpUleOp A))
  , mkT (Proxy :: Proxy (Pil.CmpUltOp A))
  , mkT (Proxy :: Proxy (Pil.ConstOp A))
  , mkT (Proxy :: Proxy (Pil.ConstPtrOp A))
  , mkT (Proxy :: Proxy (Pil.ConstFloatOp A))
  , mkT (Proxy :: Proxy (Pil.DivsOp A))
  , mkT (Proxy :: Proxy (Pil.DivsDpOp A))
  , mkT (Proxy :: Proxy (Pil.DivuOp A))
  , mkT (Proxy :: Proxy (Pil.DivuDpOp A))
  , mkT (Proxy :: Proxy (Pil.FabsOp A))
  , mkT (Proxy :: Proxy (Pil.FaddOp A))
  , mkT (Proxy :: Proxy (Pil.FcmpEOp A))
  , mkT (Proxy :: Proxy (Pil.FcmpGeOp A))
  , mkT (Proxy :: Proxy (Pil.FcmpGtOp A))
  , mkT (Proxy :: Proxy (Pil.FcmpLeOp A))
  , mkT (Proxy :: Proxy (Pil.FcmpLtOp A))
  , mkT (Proxy :: Proxy (Pil.FcmpNeOp A))
  , mkT (Proxy :: Proxy (Pil.FcmpOOp A))
  , mkT (Proxy :: Proxy (Pil.FcmpUoOp A))
  , mkT (Proxy :: Proxy (Pil.FdivOp A))
  , mkT (Proxy :: Proxy (Pil.FloatConvOp A))
  , mkT (Proxy :: Proxy (Pil.FloatToIntOp A))
  , mkT (Proxy :: Proxy (Pil.FloorOp A))
  , mkT (Proxy :: Proxy (Pil.FmulOp A))
  , mkT (Proxy :: Proxy (Pil.FnegOp A))
  , mkT (Proxy :: Proxy (Pil.FsqrtOp A))
  , mkT (Proxy :: Proxy (Pil.FsubOp A))
  , mkT (Proxy :: Proxy (Pil.FtruncOp A))
  , mkT (Proxy :: Proxy (Pil.ImportOp A))
  , mkT (Proxy :: Proxy (Pil.IntToFloatOp A))
  , mkT (Proxy :: Proxy (Pil.LoadOp A))
  , mkT (Proxy :: Proxy (Pil.LowPartOp A))
  , mkT (Proxy :: Proxy (Pil.LslOp A))
  , mkT (Proxy :: Proxy (Pil.LsrOp A))
  , mkT (Proxy :: Proxy (Pil.ModsOp A))
  , mkT (Proxy :: Proxy (Pil.ModsDpOp A))
  , mkT (Proxy :: Proxy (Pil.ModuOp A))
  , mkT (Proxy :: Proxy (Pil.ModuDpOp A))
  , mkT (Proxy :: Proxy (Pil.MulOp A))
  , mkT (Proxy :: Proxy (Pil.MulsDpOp A))
  , mkT (Proxy :: Proxy (Pil.MuluDpOp A))
  , mkT (Proxy :: Proxy (Pil.NegOp A))
  , mkT (Proxy :: Proxy (Pil.NotOp A))
  , mkT (Proxy :: Proxy (Pil.OrOp A))
  , mkT (Proxy :: Proxy (Pil.RlcOp A))
  , mkT (Proxy :: Proxy (Pil.RolOp A))
  , mkT (Proxy :: Proxy (Pil.RorOp A))
  , mkT (Proxy :: Proxy (Pil.RoundToIntOp A))
  , mkT (Proxy :: Proxy (Pil.RrcOp A))
  , mkT (Proxy :: Proxy (Pil.SbbOp A))
  , mkT (Proxy :: Proxy (Pil.SubOp A))
  , mkT (Proxy :: Proxy (Pil.SxOp A))
  , mkT (Proxy :: Proxy (Pil.TestBitOp A))
  , mkT (Proxy :: Proxy (Pil.VarPhiOp A))
  , mkT (Proxy :: Proxy (Pil.VarJoinOp A))
  , mkT (Proxy :: Proxy (Pil.VarOp A))
  , mkT (Proxy :: Proxy (Pil.VarFieldOp A))
  , mkT (Proxy :: Proxy (Pil.XorOp A))
  , mkT (Proxy :: Proxy (Pil.ZxOp A))

  , mkT (Proxy :: Proxy (Pil.ExtractOp A))
  , mkT (Proxy :: Proxy (Pil.StrCmpOp A))
  , mkT (Proxy :: Proxy (Pil.StrNCmpOp A))
  , mkT (Proxy :: Proxy (Pil.MemCmpOp A))
  , mkT (Proxy :: Proxy (Pil.ConstStrOp A))
  , mkT (Proxy :: Proxy (Pil.StackLocalAddrOp A))
  , mkT (Proxy :: Proxy (Pil.UpdateVarOp A))
    -- memory address specifier ops
  , mkT (Proxy :: Proxy (Pil.FieldAddrOp A))  -- struct
  , mkT (Proxy :: Proxy (Pil.ConstBoolOp A))
  , mkT (Proxy :: Proxy (Pil.BranchCondOp A))

  , mkT (Proxy :: Proxy Pil.StackOffset)
  

  -- types from Web.Pil
  , mkT (Proxy :: Proxy (WebPil.PilType A))
  , mkT (Proxy :: Proxy (WebPil.TIntOp A))
  , mkT (Proxy :: Proxy (WebPil.TFloatOp A))
  , mkT (Proxy :: Proxy (WebPil.TBitVectorOp A))
  , mkT (Proxy :: Proxy (WebPil.TPointerOp A))
  , mkT (Proxy :: Proxy (WebPil.TArrayOp A))
  , mkT (Proxy :: Proxy (WebPil.TFunctionOp A))


  , mkT (Proxy :: Proxy WebPil.TypeError)
  , mkT (Proxy :: Proxy WebPil.TypeReport)
  , mkT (Proxy :: Proxy WebPil.TypedExpr)
  , mkT (Proxy :: Proxy WebPil.DeepSymType)
  
  , mkT (Proxy :: Proxy Ch.Sym)
  , mkT (Proxy :: Proxy (Ch.InfoExpression A))
  , mkT (Proxy :: Proxy Ch.SymInfo)

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
  { _typePackage = "blaze-ui" -- deprecated?
  , _typeModule = "Data.Word64"
  , _typeName = "Word64"
  , _typeParameters = []
  }

psInt64 :: PB.PSType
psInt64 = PB.TypeInfo
  { _typePackage = "blaze-ui" -- deprecated?
  , _typeModule = "Data.Int64"
  , _typeName = "Int64"
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
word64Bridge = PB.typeName ^== "Word64" >> return psWord64

int64Bridge :: PB.BridgePart
int64Bridge = PB.typeName ^== "Int64" >> return psInt64

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
