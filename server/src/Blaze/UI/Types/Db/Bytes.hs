{-# OPTIONS_GHC -fno-warn-orphans #-}

module Blaze.UI.Types.Db.Bytes where

import Blaze.UI.Prelude hiding ((:*:))

import qualified Prelude as P
import Database.Selda
import Database.Selda.SqlType ( Lit(LText, LCustom)
                              , SqlTypeRep(TBlob, TText)
                              , SqlValue(SqlString)
                              )


-- oh no, it's an orphan!
instance SqlType Bytes where
   mkLit (Bytes x) = LCustom TBlob . LText . show $ x

   sqlType _ = TText

   fromSql (SqlString s) = case readMaybe (cs s) of
     Nothing -> P.error $ "Cannot convert " <> cs s <> " to Bytes"
     Just n -> Bytes n
   fromSql x = P.error $ "Unexpected sql field type: " <> show x

   defaultValue = LCustom TText (LText "")
