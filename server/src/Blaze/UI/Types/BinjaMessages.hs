{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TemplateHaskell #-}

module Blaze.UI.Types.BinjaMessages where

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



