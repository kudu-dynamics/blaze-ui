module Blaze.UI.Types.Cfg where

import Blaze.UI.Prelude hiding (Symbol)

import Blaze.Types.Pil (Stmt)
import Blaze.Types.Cfg ( CfNode, CfEdge(CfEdge), Cfg )
import qualified Blaze.Types.Cfg as Cfg
import qualified Blaze.Graph as G
import qualified Data.HashMap.Strict as HashMap
import Blaze.Pretty (Token, mkTokenizerCtx, runTokenize)
import Blaze.Cfg.Interprocedural (
  InterCfg,
  unInterCfg,
 )
import System.Random (Random)
import Database.Selda.SqlType ( Lit(LCustom)
                              , SqlTypeRep(TBlob)
                              , SqlType
                              )
import qualified Database.Selda.SqlType as Sql

newtype CfgId = CfgId UUID
  deriving (Eq, Ord, Show, Generic)
  deriving newtype (Random)
  deriving anyclass (Hashable, ToJSON, FromJSON, ToJSONKey, FromJSONKey)

instance SqlType CfgId where
   mkLit (CfgId x) = LCustom TBlob $ Sql.mkLit x
   sqlType _ = TBlob
   fromSql x = CfgId $ Sql.fromSql x
   defaultValue = LCustom TBlob (Sql.defaultValue :: Lit UUID)

data CfgTransport a = CfgTransport
  { edges :: [CfEdge ()]
  , root :: CfNode ()
  , nodes :: [(CfNode (), CfNode a)]
  } deriving (Eq, Ord, Show, Generic, ToJSON, FromJSON, Functor)

convertInterCfg :: InterCfg -> CfgTransport [[Token]]
convertInterCfg = convertPilCfg . unInterCfg

convertPilCfg :: Cfg [Stmt] -> CfgTransport [[Token]]
convertPilCfg cfg = toTransport (fmap (runTokenize tokenizerCtx)) cfg
  where
    tokenizerCtx = mkTokenizerCtx cfg

toTransport :: forall a b. (a -> b) -> Cfg a -> CfgTransport b
toTransport f pcfg = CfgTransport
  { edges =  edges'
  , root = root'
  , nodes = textNodes'
  }
  where
    root' = void $ pcfg ^. #root

    nodes' :: [(CfNode (), CfNode a)]
    nodes' = HashMap.toList $ pcfg ^. #graph . #nodeAttrMap

    textNodes' :: [(CfNode (), CfNode b)]
    textNodes' = fmap g nodes'
      where
        g :: (CfNode (), CfNode a) -> (CfNode (), CfNode b)
        g (a, b) = (a, f <$> b)

    edges' :: [CfEdge ()]
    edges' = fmap Cfg.fromLEdge . G.edges $ pcfg ^. #graph


fromTransport :: (Eq a, Hashable a) => CfgTransport a -> Cfg a
fromTransport t = Cfg.mkCfg root' nodes' edges'
  where
    nodeMap = HashMap.fromList $ t ^. #nodes

    fullNode = fromJust . flip HashMap.lookup nodeMap

    fullEdge e = CfEdge
      { src = fullNode $ e ^. #src
      , dst = fullNode $ e ^. #dst
      , branchType = e ^. #branchType
      }

    root' = fullNode $ t ^. #root

    nodes' = snd <$> t ^. #nodes

    edges' = fullEdge <$> t ^. #edges
