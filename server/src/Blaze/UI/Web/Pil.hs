module Blaze.UI.Web.Pil where

import Blaze.UI.Prelude hiding (TypeError)
import qualified Blaze.Types.Pil as Pil
import Blaze.Types.Pil.Checker (InfoExpression, SymInfo)
import qualified Blaze.Types.Pil.Checker as Ch
import qualified Data.Text as Text
import qualified Data.HashMap.Strict as HashMap

newtype Sym = Sym Int
  deriving (Eq, Ord, Show, Generic)

instance ToJSON Sym
instance FromJSON Sym

data TypeError = TypeError
  { stmtOrigin :: Int
  , sym :: Sym
  , error :: Text
  } deriving (Show, Eq, Ord, Generic)

instance ToJSON TypeError
instance FromJSON TypeError

data TypeReport = TypeReport
  { typedStmts :: [(Int, Pil.Statement TypedExpr)]
  , errors :: [TypeError]
  , varSymTypeMap :: [(Pil.PilVar, DeepSymType)]
  , varSymMap :: [(Pil.PilVar, Sym)]
  } deriving (Show, Eq, Ord, Generic)

instance ToJSON TypeReport
instance FromJSON TypeReport
              

data TypedExpr = TypedExpr
  { sym :: Sym
  , op :: Text
  , pilType :: Maybe DeepSymType
  , args :: [TypedExpr]
  } deriving (Eq, Ord, Show, Generic)

instance ToJSON TypedExpr
instance FromJSON TypedExpr



toTypeError :: Ch.UnifyConstraintsError Ch.DeepSymType -> TypeError
toTypeError x = TypeError
  { stmtOrigin = x ^. #stmtOrigin
  , sym = let (Ch.Sym s) = x ^. #sym in Sym s
  , error = cs . pshow $ x ^. #error
  }

-- TODO: use Generic to get constructor string
showOpName :: Show a => Pil.ExprOp a -> Text
showOpName = fst . Text.breakOn " " . show

showType :: Ch.DeepSymType -> Text
showType = show

toTypedExpr :: InfoExpression (SymInfo, Maybe Ch.DeepSymType) -> TypedExpr
toTypedExpr x = TypedExpr
  { sym = let (Ch.Sym s) = x ^. #info . _1 . #sym in Sym s
  , op = showOpName $ x ^. #op
  , pilType = convertDeepSymType <$> x ^. #info . _2
  , args = fmap toTypedExpr . foldr (:) [] $ x ^. #op
  }


toTypeReport :: Ch.TypeReport -> TypeReport
toTypeReport x = TypeReport
  { typedStmts = fmap f $ x ^. #symTypeStmts
  , errors = fmap toTypeError $ x ^. #errors
  , varSymTypeMap = HashMap.toList $ convertDeepSymType <$> x ^. #varSymTypeMap
  , varSymMap = HashMap.toList $ convertSym <$> x ^. #varSymMap
  }
  where
    f (stmtIndex, stmt) = (stmtIndex, fmap toTypedExpr stmt)





----------- Types conversion -----
-- this is because purescript can't decode sum types with unsafe records
-- TODO: maybe change type in Checker to use these Op types

type BitWidth = Bits
type ByteWidth = Bytes


data TIntOp t = TIntOp
  { bitWidth :: t
  , signed :: t
  } deriving (Eq, Ord, Read, Show, Functor, Foldable, Traversable, Generic, ToJSON, FromJSON)

data TFloatOp t = TFloatOp
  { bitWidth :: t
  } deriving (Eq, Ord, Read, Show, Functor, Foldable, Traversable, Generic, ToJSON, FromJSON)

data TBitVectorOp t = TBitVectorOp
  { bitWidth :: t
  } deriving (Eq, Ord, Read, Show, Functor, Foldable, Traversable, Generic, ToJSON, FromJSON)

data TPointerOp t = TPointerOp
  { bitWidth :: t
  , pointeeType :: t
  } deriving (Eq, Ord, Read, Show, Functor, Foldable, Traversable, Generic, ToJSON, FromJSON)

data TArrayOp t = TArrayOp
  { len :: t
  , elemType :: t
  } deriving (Eq, Ord, Read, Show, Functor, Foldable, Traversable, Generic, ToJSON, FromJSON)

-- data TRecordOp t = TRecordOp
--   { fields :: HashMap BitOffset t
--   -- todo: change bitwidth to 't'?
--   -- TODO: change bitwidth to signed offset
--   } deriving (Eq, Ord, Read, Show, Functor, Foldable, Traversable, Generic, ToJSON, FromJSON)
  
data TFunctionOp t = TFunctionOp
  { ret :: t
  , params :: [t]
  } deriving (Eq, Ord, Read, Show, Functor, Foldable, Traversable, Generic, ToJSON, FromJSON)


data PilType t = TBool
               | TChar
               
               | TInt (TIntOp t)
               | TFloat (TFloatOp t)
               | TBitVector (TBitVectorOp t)
               | TPointer (TPointerOp t) 

--               | TCString { len :: t }

               | TArray (TArrayOp t)
               | TRecord [(BitOffset, t)]
               
               -- Bottom is labeled with error info
               | TBottom Sym
               | TFunction (TFunctionOp t)
              
               -- type level values for some dependent-type action
               | TVBitWidth BitWidth
               | TVLength Word64
               | TVSign Bool    
               deriving (Eq, Ord, Show, Functor, Foldable, Traversable, Generic)

instance FromJSON t => FromJSON (PilType t)
instance ToJSON t => ToJSON (PilType t)

data DeepSymType = DSVar Sym
                 | DSRecursive Sym (PilType DeepSymType)
                 | DSType (PilType DeepSymType)
                 deriving (Eq, Ord, Show, Generic, ToJSON, FromJSON)


convertSym :: Ch.Sym -> Sym
convertSym (Ch.Sym s) = Sym s

convertDeepSymType :: Ch.DeepSymType -> DeepSymType
convertDeepSymType = \case
  Ch.DSVar s -> DSVar (convertSym s)
  Ch.DSRecursive s pt -> DSRecursive (convertSym s) (f pt)
  Ch.DSType pt -> DSType (f pt)
  where
    f = fmap convertDeepSymType . convertPilType

convertPilType :: Ch.PilType t -> PilType t
convertPilType = \case
  Ch.TBool -> TBool
  Ch.TChar -> TChar
  Ch.TInt w s -> TInt $ TIntOp w s
  Ch.TFloat w -> TFloat $ TFloatOp w
  Ch.TBitVector w ->  TBitVector $ TBitVectorOp w
  Ch.TPointer w t -> TPointer $ TPointerOp w t
  Ch.TArray l t -> TArray $ TArrayOp l t
  Ch.TRecord xs -> TRecord (HashMap.toList xs)
  Ch.TBottom (Ch.Sym s) -> TBottom (Sym s)
  Ch.TFunction r xs -> TFunction $ TFunctionOp r xs
  Ch.TVBitWidth w -> TVBitWidth w
  Ch.TVLength l -> TVLength l
  Ch.TVSign b -> TVSign b


