module Blaze.UI.Components.FunctionView where

import Data.Monoid
import Prelude

import Blaze.Types.CallGraph (_Function)
import Blaze.Types.CallGraph as CG
import Blaze.Types.Pil (CallDest, CallOp(..), ConstStrOp(..), ExprOp(..), ExtractOp(..), MemCmpOp(..), Statement, StrCmpOp(..), StrNCmpOp(..), UpdateVarOp(..), VarFieldOp(..), VarJoinOp(..), VarOp(..), VarPhiOp(..), _ConstBoolOp, _FieldAddrOp, _StackLocalAddrOp)
import Blaze.Types.Pil as Pil
import Blaze.Types.Pil.Checker (InfoExpression(..), Sym(..), SymInfo(..), _SymInfo)
import Blaze.Types.Pil.Common (PilVar(..), StackOffset(..), _StackOffset)
import Blaze.Types.Pil.Op.AdcOp (_AdcOp)
import Blaze.Types.Pil.Op.AddOp (_AddOp)
import Blaze.Types.Pil.Op.AddOverflowOp (_AddOverflowOp)
import Blaze.Types.Pil.Op.AndOp (_AndOp)
import Blaze.Types.Pil.Op.AsrOp (_AsrOp)
import Blaze.Types.Pil.Op.BoolToIntOp (_BoolToIntOp)
import Blaze.Types.Pil.Op.CeilOp (_CeilOp)
import Blaze.Types.Pil.Op.CmpEOp (_CmpEOp)
import Blaze.Types.Pil.Op.CmpNeOp (_CmpNeOp)
import Blaze.Types.Pil.Op.CmpSgeOp (_CmpSgeOp)
import Blaze.Types.Pil.Op.CmpSgtOp (_CmpSgtOp)
import Blaze.Types.Pil.Op.CmpSleOp (_CmpSleOp)
import Blaze.Types.Pil.Op.CmpSltOp (_CmpSltOp)
import Blaze.Types.Pil.Op.CmpUgeOp (_CmpUgeOp)
import Blaze.Types.Pil.Op.CmpUgtOp (_CmpUgtOp)
import Blaze.Types.Pil.Op.CmpUleOp (_CmpUleOp)
import Blaze.Types.Pil.Op.CmpUltOp (_CmpUltOp)
import Blaze.Types.Pil.Op.ConstFloatOp (_ConstFloatOp)
import Blaze.Types.Pil.Op.ConstOp (_ConstOp)
import Blaze.Types.Pil.Op.ConstPtrOp (_ConstPtrOp)
import Blaze.Types.Pil.Op.DivsDpOp (_DivsDpOp)
import Blaze.Types.Pil.Op.DivsOp (_DivsOp)
import Blaze.Types.Pil.Op.DivuDpOp (_DivuDpOp)
import Blaze.Types.Pil.Op.DivuOp (_DivuOp)
import Blaze.Types.Pil.Op.FabsOp (_FabsOp)
import Blaze.Types.Pil.Op.FaddOp (_FaddOp)
import Blaze.Types.Pil.Op.FcmpEOp (_FcmpEOp)
import Blaze.Types.Pil.Op.FcmpGeOp (_FcmpGeOp)
import Blaze.Types.Pil.Op.FcmpGtOp (_FcmpGtOp)
import Blaze.Types.Pil.Op.FcmpLeOp (_FcmpLeOp)
import Blaze.Types.Pil.Op.FcmpLtOp (_FcmpLtOp)
import Blaze.Types.Pil.Op.FcmpNeOp (_FcmpNeOp)
import Blaze.Types.Pil.Op.FcmpOOp (_FcmpOOp)
import Blaze.Types.Pil.Op.FcmpUoOp (_FcmpUoOp)
import Blaze.Types.Pil.Op.FdivOp (_FdivOp)
import Blaze.Types.Pil.Op.FloatConvOp (_FloatConvOp)
import Blaze.Types.Pil.Op.FloatToIntOp (_FloatToIntOp)
import Blaze.Types.Pil.Op.FloorOp (_FloorOp)
import Blaze.Types.Pil.Op.FmulOp (_FmulOp)
import Blaze.Types.Pil.Op.FnegOp (_FnegOp)
import Blaze.Types.Pil.Op.FsqrtOp (_FsqrtOp)
import Blaze.Types.Pil.Op.FsubOp (_FsubOp)
import Blaze.Types.Pil.Op.FtruncOp (_FtruncOp)
import Blaze.Types.Pil.Op.ImportOp (_ImportOp)
import Blaze.Types.Pil.Op.IntToFloatOp (_IntToFloatOp)
import Blaze.Types.Pil.Op.LoadOp (LoadOp(..), _LoadOp)
import Blaze.Types.Pil.Op.LowPartOp (_LowPartOp)
import Blaze.Types.Pil.Op.LslOp (_LslOp)
import Blaze.Types.Pil.Op.LsrOp (_LsrOp)
import Blaze.Types.Pil.Op.ModsDpOp (_ModsDpOp)
import Blaze.Types.Pil.Op.ModsOp (_ModsOp)
import Blaze.Types.Pil.Op.ModuDpOp (_ModuDpOp)
import Blaze.Types.Pil.Op.ModuOp (_ModuOp)
import Blaze.Types.Pil.Op.MulOp (_MulOp)
import Blaze.Types.Pil.Op.MulsDpOp (_MulsDpOp)
import Blaze.Types.Pil.Op.MuluDpOp (_MuluDpOp)
import Blaze.Types.Pil.Op.NegOp (_NegOp)
import Blaze.Types.Pil.Op.NotOp (_NotOp)
import Blaze.Types.Pil.Op.OrOp (_OrOp)
import Blaze.Types.Pil.Op.RlcOp (_RlcOp)
import Blaze.Types.Pil.Op.RolOp (_RolOp)
import Blaze.Types.Pil.Op.RorOp (_RorOp)
import Blaze.Types.Pil.Op.RoundToIntOp (_RoundToIntOp)
import Blaze.Types.Pil.Op.RrcOp (_RrcOp)
import Blaze.Types.Pil.Op.SbbOp (_SbbOp)
import Blaze.Types.Pil.Op.SubOp (_SubOp)
import Blaze.Types.Pil.Op.SxOp (_SxOp)
import Blaze.Types.Pil.Op.TestBitOp (_TestBitOp)
import Blaze.Types.Pil.Op.XorOp (XorOp(..))
import Blaze.Types.Pil.Op.ZxOp (ZxOp(..))
import Blaze.UI.Prelude (showHex)
import Blaze.UI.Socket (Conn(..))
import Blaze.UI.Socket as Socket
import Blaze.UI.Types (Nav(..))
import Blaze.UI.Types.WebMessages (ServerToWeb(..), WebToServer(..), _SWFunctionTypeReport, _SWFunctionsList, _SWPilType)
import Blaze.UI.Web.Pil (DeepSymType, TypeReport(..), TypedExpr(..))
import Concur.Core (Widget)
import Concur.Core.Types (affAction, pulse)
import Concur.MaterialUI as M
import Concur.React (HTML, componentClass, renderComponent)
import Concur.React.DOM (div_, h2_, hr', text)
import Concur.React.DOM as D
import Concur.React.Props (ReactProps)
import Concur.React.Props as P
import Concur.React.Run (runWidgetInDom)
import Control.Alt ((<|>))
import Control.Monad.Rec.Class (forever)
import Control.Monad.State (modify, modify_)
import Control.Monad.State.Class (get, put)
import Control.Monad.State.Trans (StateT, runStateT)
import Control.MultiAlternative (orr)
import Control.Wire as Wire
import Data.Array as Array
import Data.BinaryAnalysis (Address(..), Bits(..), ByteOffset(..), Bytes(..), _ByteOffset, _Bytes)
import Data.Foldable (fold, foldr)
import Data.Generic.Rep (class Generic)
import Data.Generic.Rep.Show (genericShow)
import Data.Int as Int
import Data.Lens (view, (^.), (^?))
import Data.Lens.Iso.Newtype (_Newtype)
import Data.Map (Map)
import Data.Map as Map
import Data.Maybe (Maybe(..), fromJust, fromMaybe, maybe)
import Data.String (Pattern(..))
import Data.String as String
import Data.Traversable (traverse)
import Data.Tuple (Tuple(..), curry, uncurry)
import Data.Tuple.Nested ((/\), type (/\))
import Effect (Effect)
import Effect.Aff (Milliseconds(..), delay, forkAff)
import Effect.Aff.Class (liftAff)
import Effect.Class (liftEffect)
import Effect.Class.Console (log)
import Effect.Random (random)
import Pipes.Prelude (mapM)
import React (ReactClass)
import React.Basic.Hooks as Hooks

type SymExpression = InfoExpression SymInfo

type FuncViewState = { conn :: Conn ServerToWeb WebToServer
                     , highlightedSym :: Maybe Sym
                     , varSymTypeMap :: Map PilVar DeepSymType
                     , varSymMap :: Map PilVar Sym
                     , symStmts :: Array (Tuple Int (Statement SymExpression))
                     }

data StmtAction = HighlightSym Sym
                | Unhighlight

derive instance genericStmtAction :: Generic StmtAction _
instance showStmtAction :: Show StmtAction where
  show x = genericShow x



type FuncViewWidget a = StateT FuncViewState (Widget HTML) a

dispTypedExpr :: TypedExpr
              -> FuncViewWidget StmtAction
dispTypedExpr (TypedExpr x) =
  D.span [ P.className "pil-expr" ]
  [ D.span [ P.className "pil-expr-op" ] [ D.text x.op ]
  , orr $ dispArg <$> x.args
  ]
  where
    dispArg arg = do
      D.span [ P.className "pil-expr-arg" ]
        [ D.text "("
        , dispTypedExpr arg
        , D.text ")"
        ]

intercalate :: forall a. a -> Array a -> Array a
intercalate x xs = case Array.uncons xs of
  Nothing -> []
  Just {head: y, tail: ys} -> case Array.head ys of
    Nothing -> [y]
    Just _ -> [y, x] <> intercalate x ys

dispAddr :: Address -> FuncViewWidget StmtAction
dispAddr (Address (Bytes x)) = D.text $ showHex x

dispByteOffset :: ByteOffset -> FuncViewWidget StmtAction
dispByteOffset = D.text <<< showHex <<< view _ByteOffset

dispStackOffset :: StackOffset -> FuncViewWidget StmtAction
dispStackOffset (StackOffset x) =
  D.text <<< showHex $ x.offset ^. _ByteOffset

classes :: forall a. Array String -> ReactProps a
classes = P.className <<< foldr (<>) "" <<< intercalate " "

curly :: forall a. FuncViewWidget a -> FuncViewWidget a
curly x = orr [ D.text "{"
              , x
              , D.text "}"
              ]

bracket :: forall a. FuncViewWidget a -> FuncViewWidget a
bracket x = orr [ D.text "["
                , x
                , D.text "]"
                ]

paren :: forall a. FuncViewWidget a -> FuncViewWidget a
paren x = orr [ D.text "("
              , x
              , D.text ")"
              ]


dispExprOp :: SymInfo
           -> ExprOp SymExpression
           -> FuncViewWidget StmtAction
dispExprOp (SymInfo sinfo) xop = case xop of
  (Pil.ADC op) -> dispBinCarryOp "adc" $ op ^. _AdcOp
  (Pil.ADD op) -> infixBinOp "+" $ op ^. _AddOp
  (Pil.ADD_OVERFLOW op) -> dispBinOp "addOf" $ op ^. _AddOverflowOp
  (Pil.AND op) -> infixBinOp "&&" $ op ^. _AndOp
  (Pil.ASR op) -> dispBinOp "asr" $ op ^. _AsrOp
  (Pil.BOOL_TO_INT op) -> dispUnOp "boolToInt" $ op ^. _BoolToIntOp
  (Pil.CEIL op) -> dispUnOp "ceil" $ op ^. _CeilOp
  (Pil.CMP_E op) -> infixBinOp "==" $ op ^. _CmpEOp
  (Pil.CMP_NE op) -> infixBinOp "!=" $ op ^. _CmpNeOp
  (Pil.CMP_SGE op) -> infixBinOp "s>=" $ op ^. _CmpSgeOp
  (Pil.CMP_SGT op) -> infixBinOp "s>" $ op ^. _CmpSgtOp
  (Pil.CMP_SLE op) -> infixBinOp "s<=" $ op ^. _CmpSleOp
  (Pil.CMP_SLT op) -> infixBinOp "s<" $ op ^. _CmpSltOp
  (Pil.CMP_UGE op) -> infixBinOp "u>=" $ op ^. _CmpUgeOp
  (Pil.CMP_UGT op) -> infixBinOp "u>" $ op ^. _CmpUgtOp
  (Pil.CMP_ULE op) -> infixBinOp "u<=" $ op ^. _CmpUleOp
  (Pil.CMP_ULT op) -> infixBinOp "u<" $ op ^. _CmpUltOp

  (Pil.CONST op) -> dispConst "const" $ op ^. _ConstOp
  (Pil.CONST_BOOL op) -> dispConst "bool" $ op ^. _ConstBoolOp
  (Pil.CONST_FLOAT op) -> dispConst "float" $ op ^. _ConstFloatOp
  (Pil.CONST_PTR op) -> dispConst "ptr" $ op ^. _ConstPtrOp
  
  (Pil.DIVS op) -> dispBinOp "divs" $ op ^. _DivsOp
  (Pil.DIVS_DP op) -> dispBinOp "divsDP" $ op ^. _DivsDpOp
  (Pil.DIVU op) -> dispBinOp "divu" $ op ^. _DivuOp
  (Pil.DIVU_DP op) -> dispBinOp "divuDP" $ op ^. _DivuDpOp
  (Pil.FABS op) -> dispUnOp "fabs" $ op ^. _FabsOp

  (Pil.FADD op) -> infixBinOp "f+" $ op ^. _FaddOp
  (Pil.FCMP_E op) -> infixBinOp "f==" $ op ^. _FcmpEOp
  (Pil.FCMP_GE op) -> infixBinOp "f>=" $ op ^. _FcmpGeOp
  (Pil.FCMP_GT op) -> infixBinOp "f>" $ op ^. _FcmpGtOp
  (Pil.FCMP_LE op) -> infixBinOp "f<=" $ op ^. _FcmpLeOp
  (Pil.FCMP_LT op) -> infixBinOp "f<" $ op ^. _FcmpLtOp
  (Pil.FCMP_NE op) -> infixBinOp "f!=" $ op ^. _FcmpNeOp
  (Pil.FCMP_O op) -> dispBinOp "fcmpO" $ op ^. _FcmpOOp
  (Pil.FCMP_UO op) -> dispBinOp "fcmpUO" $ op ^. _FcmpUoOp
  (Pil.FDIV op) -> dispBinOp "fdiv" $ op ^. _FdivOp

  (Pil.FIELD_ADDR op) ->
    expr "fieldAddr"
    [ bracket $ dispExpr (op ^. _FieldAddrOp).baseAddr
    , D.text <<< showHex $ (op ^. _FieldAddrOp).offset ^. _ByteOffset
    ]

  (Pil.FLOAT_CONV op) -> dispUnOp "floatConv" $ op ^. _FloatConvOp
  (Pil.FLOAT_TO_INT op) -> dispUnOp "floatToInt" $ op ^. _FloatToIntOp
  (Pil.FLOOR op) -> dispUnOp "floor" $ op ^. _FloorOp
  (Pil.FMUL op) -> dispBinOp "fmul" $ op ^. _FmulOp
  (Pil.FNEG op) -> dispUnOp "fneg" $ op ^. _FnegOp
  (Pil.FSQRT op) -> dispUnOp "fsqrt" $ op ^. _FsqrtOp
  (Pil.FSUB op) -> dispBinOp "fsub" $ op ^. _FsubOp
  (Pil.FTRUNC op) -> dispUnOp "ftrunc" $ op ^. _FtruncOp
  (Pil.IMPORT op) -> dispConst "import" $ op ^. _ImportOp
  (Pil.INT_TO_FLOAT op) -> dispUnOp "intToFloat" $ op ^. _IntToFloatOp
  (Pil.LOAD (LoadOp op)) -> D.span [] [ bracket $ dispExpr op.src ]
  -- TODO: add memory versions for all SSA ops
  (Pil.LOW_PART op) -> dispUnOp "lowPart" $ op ^. _LowPartOp
  (Pil.LSL op) -> dispBinOp "lsl" $ op ^. _LslOp
  (Pil.LSR op) -> dispBinOp "lsr" $ op ^. _LsrOp
  (Pil.MODS op) -> dispBinOp "mods" $ op ^. _ModsOp
  (Pil.MODS_DP op) -> dispBinOp "modsDP" $ op ^. _ModsDpOp
  (Pil.MODU op) -> dispBinOp "modu" $ op ^. _ModuOp
  (Pil.MODU_DP op) -> dispBinOp "moduDP" $ op ^. _ModuDpOp
  (Pil.MUL op) -> dispBinOp "mul" $ op ^. _MulOp
  (Pil.MULS_DP op) -> dispBinOp "mulsDP" $ op ^. _MulsDpOp
  (Pil.MULU_DP op) -> dispBinOp "muluDP" $ op ^. _MuluDpOp
  (Pil.NEG op) -> dispUnOp "neg" $ op ^. _NegOp
  (Pil.NOT op) -> dispUnOp "not" $ op ^. _NotOp
  (Pil.OR op) -> dispBinOp "or" $ op ^. _OrOp
  -- -- TODO: Need to add carry
  (Pil.RLC op) -> dispBinCarryOp "rlc" $ op ^. _RlcOp
  (Pil.ROL op) -> dispBinOp "rol" $ op ^. _RolOp
  (Pil.ROR op) -> dispBinOp "ror" $ op ^. _RorOp
  (Pil.ROUND_TO_INT op) -> dispUnOp "roundToInt" $ op ^. _RoundToIntOp
  -- -- TODO: Need to add carry
  (Pil.RRC op) -> dispBinCarryOp "rrc" $ op ^. _RrcOp
  (Pil.SBB op) -> dispBinCarryOp "sbb" $ op ^. _SbbOp
  (Pil.STACK_LOCAL_ADDR op) ->
    expr "stackLocalAddr"
    [ paren <<< dispStackOffset $ (op ^. _StackLocalAddrOp).stackOffset
    ]
  (Pil.SUB op) -> dispBinOp "sub" $ op ^. _SubOp
  (Pil.SX op) -> dispUnOp "sx" $ op ^. _SxOp
  (Pil.TEST_BIT op) -> dispBinOp "testBit" $ op ^. _TestBitOp
  (Pil.UNIMPL t) -> expr "unimpl" [paren $ D.text t]
  (Pil.UPDATE_VAR (UpdateVarOp op)) ->
    expr "updateVar"
    [ dispPilVar op.dest
    , D.text <<< showHex $ op.offset ^. _ByteOffset
    , paren $ dispExpr op.src
    ]
  (Pil.VAR_PHI (VarPhiOp op)) ->
    expr "varPhi"
    [ dispPilVar op.dest
    , bracket <<< orr $ dispPilVar <$> op.src
    ]
  (Pil.VAR_JOIN (VarJoinOp op)) ->
    expr "varJoin" [dispPilVar op.high, dispPilVar op.low]
  (Pil.VAR (VarOp op)) -> dispPilVar op.src
  -- TODO: Add field offset
  (Pil.VAR_FIELD (VarFieldOp op)) ->
    expr "varField" [ dispPilVar op.src
                    , dispByteOffset op.offset
                    ]
  (Pil.XOR (XorOp op)) -> dispBinOp "xor" op
  (Pil.ZX (ZxOp op)) -> dispUnOp "zx" op
  (Pil.CALL (CallOp op)) -> 
      expr "call" [ D.text $ fromMaybe "(Nothing)" op.name
                  , paren $ dispCallDest op.dest
                  , paren
                    <<< orr
                    <<< intercalate (D.text ", ")
                    $ dispExpr <$> op.params
                  ]
  (Pil.StrCmp (StrCmpOp op)) -> dispBinOp "strcmp" op
  (Pil.StrNCmp (StrNCmpOp op)) ->
    expr "strncmp"
    [ D.text $ show op.len
    , paren <<< dispExpr $ op.left
    , paren <<< dispExpr $ op.right
    ]
  (Pil.MemCmp (MemCmpOp op)) ->
    expr "memcmp"
    [ paren $ dispExpr op.left
    , paren $ dispExpr op.right
    , D.text <<< show $ op.size ^. _Bytes
    ]
  -- -- TODO: Should ConstStr also use const rather than value as field name?
  (Pil.ConstStr (ConstStrOp op)) ->
    expr "constStr" [ D.text $ show op.value ]
  (Pil.Extract (ExtractOp op)) ->
    expr "extract"
    [ paren $ dispExpr op.src
    , D.text $ show op.offset
    ]

  _ -> todo
  where
    isHighlighted :: FuncViewWidget Boolean
    isHighlighted = do
      st <- get
      case st.highlightedSym of
        Nothing -> pure false
        Just s -> pure $ s == sinfo.sym
      
    todo = D.span [ P.className "pil-expr-op" ] [D.text " todo "]

    space = D.text " "

    infixOp :: String
            -> FuncViewWidget StmtAction
            -> FuncViewWidget StmtAction
            -> FuncViewWidget StmtAction
    infixOp opStr a b = do
      highlighted <- isHighlighted
      D.span
        []
        [ a
        , D.span [ P.onClick $> HighlightSym sinfo.sym
                 , classes $ ["pointer-cursor", "pil-expr-op"]
                   <> if highlighted then ["expr-sym-highlight"] else []
                 ]
          [ D.text opStr ]
        , b
        ]

    infixBinOp opStr op =
      infixOp opStr
      (paren $ dispExpr op.left)
      (paren $ dispExpr op.right)

    expr :: String
         -> Array (FuncViewWidget StmtAction)
         -> FuncViewWidget StmtAction
    expr opStr xs = do
      highlighted <- isHighlighted
      D.span
        []
        <<< intercalate space $ [ dispOpStr opStr ] <> xs

    dispOpStr opStr = do
      highlighted <- isHighlighted
      D.span [ P.onClick $> HighlightSym sinfo.sym
             , classes $ ["pointer-cursor", "pil-expr-op"]
                <> if highlighted then ["expr-sym-highlight"] else []
             ]
        [ D.text opStr ]

    dispUnOp opStr op = expr opStr [paren $ dispExpr op.src]

    dispBinOp opStr op =
      expr opStr [ paren $ dispExpr op.left
                 , paren $ dispExpr op.right
                 ]

    dispBinCarryOp opStr op =
      expr opStr [ paren $ dispExpr op.left
                 , paren $ dispExpr op.right
                 , paren $ dispExpr op.carry
                 ]
    
    dispConst :: forall a r. Show a => String -> { constant :: a | r } -> FuncViewWidget StmtAction
    dispConst opStr x =
      D.span [] [ dispOpStr opStr
                , D.span [ P.className "pil-expr-const-val" ]
                  [ D.text $ " " <> show x.constant ]
                ]

    dispCallDest :: CallDest SymExpression
                 -> FuncViewWidget StmtAction
    dispCallDest (Pil.CallConstPtr x) = dispConst "constPtr" $ x ^. _ConstPtrOp
    dispCallDest (Pil.CallExpr x) = dispExpr x
    dispCallDest (Pil.CallExprs xs) = orr $ paren <<< dispExpr <$> xs


dispExpr :: SymExpression
         -> FuncViewWidget StmtAction
dispExpr (InfoExpression x) =
  D.span [ P.className "pil-expr" ] [ dispExprOp x.info x.op ]


dispPilVar :: PilVar -> FuncViewWidget StmtAction
dispPilVar pv@(PilVar x) = do
  st <- get
  let msym = Map.lookup pv st.varSymMap
  let highlighted = fromMaybe false $ (==) <$> msym <*> st.highlightedSym
  r <- D.span [ classes $ ["pilvar", "pointer-cursor"]
                <> if highlighted then ["expr-sym-highlight"] else []
              , P.onClick $> (HighlightSym <$> msym)
              ]
       [ D.text x.symbol ]
  maybe (dispPilVar pv) pure r

dispStmt :: Statement SymExpression
         -> FuncViewWidget StmtAction
dispStmt stmt = case stmt of
  Pil.Def (Pil.DefOp x) ->
    D.span [] [ dispPilVar x.var
              , D.text " = "
              , dispExpr x.value
              ]
  Pil.Constraint (Pil.ConstraintOp x) ->
    D.span [] [ D.text "?: "
              , dispExpr x.condition
              ]
  Pil.Store (Pil.StoreOp x) ->
    D.span [] [ bracket $ dispExpr x.addr
              , D.text " = "
              , dispExpr x.value 
              ]
  Pil.UnimplInstr s -> todo
  Pil.UnimplMem (Pil.UnimplMemOp a) -> todo
  Pil.Undef -> todo
  Pil.Nop -> todo
  Pil.Annotation s -> todo
  Pil.EnterContext (Pil.EnterContextOp a) -> todo
  Pil.ExitContext (Pil.ExitContextOp a) -> todo
  Pil.Call (Pil.CallOp a) -> todo
  Pil.DefPhi (Pil.DefPhiOp x) ->
    D.span [] [ dispPilVar x.dest
              , D.text " = Φ"
              , orr <<< intercalate (D.text ", ") $ dispPilVar <$> x.src
              ]
    
  where
    wrapper = D.span
    todo = wrapper [] [D.text "_"]


statement :: Int
          -> Statement SymExpression
          -> FuncViewWidget StmtAction
statement index stmt =
  D.div []
  [ D.text $ show index <> ": "
  , dispStmt stmt
  ]

statements :: FuncViewWidget Unit
statements = do
  D.div []
    [ D.div [] [D.text "Statements"]
    , view ]
  where
    
    update (HighlightSym sym) = modify_ (_ {highlightedSym = Just sym})
    update Unhighlight= modify_ (_ {highlightedSym = Nothing})

    view :: forall a. FuncViewWidget a
    view = do
      st <- get
      action <- orr $ (uncurry statement) <$> st.symStmts
      log $ show action
      update action
      view

-- eventually this could add a wrapper or something
typeReport :: FuncViewWidget Unit
typeReport = statements

functionView :: Conn ServerToWeb WebToServer
             -> CG.Function
             -> Widget HTML Unit
functionView conn fn@(CG.Function func) = do
  liftEffect <<< Socket.sendMessage conn $ WSGetTypeReport fn
  (TypeReport tr) <- orr
    [ liftAff $ Socket.getMessageWith conn (_ ^? _SWFunctionTypeReport)
    , D.text "Loading type report"
    ]
  void $ runStateT typeReport
    { conn
    , highlightedSym: Nothing
    , varSymTypeMap: Map.fromFoldable tr.varSymTypeMap
    , varSymMap: Map.fromFoldable tr.varSymMap
    , symStmts: tr.symStmts
    }
