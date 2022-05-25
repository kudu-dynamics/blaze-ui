module Blaze.UI.Cfg
  ( module Blaze.UI.Cfg
  , module CfgUI
  ) where

import Blaze.UI.Prelude hiding (group)
import Blaze.UI.Types.Cfg (TypedCfg(TypedCfg), UngroupedCfg, withUngrouped, group_, typeInfoFromTypeReport, CfgId)
import qualified Blaze.UI.Types.Cfg as CfgUI
import Blaze.UI.Types (EventLoop)
import qualified Data.HashMap.Strict as HashMap
import qualified Data.HashSet as HashSet
import Blaze.Types.Cfg.Grouping (CfNode, CfEdge)
import qualified Blaze.Types.Graph as G
import Blaze.Cfg (Cfg)
import qualified Blaze.Types.Cfg as Cfg


-- | Changes CfgId key in graph cache.
-- Used whenever an auto-saved cfg is turned into a snapshot.
changeCfgId :: CfgId -> CfgId -> EventLoop ()
changeCfgId oldCid newCid = do
  cfgMapTVar <- view #cfgs <$> ask
  liftIO $ atomically $ do
    m <- readTVar cfgMapTVar
    case HashMap.lookup oldCid m of
      Nothing -> return () -- or maybe should throw an error
      Just cfg -> do
        writeTVar cfgMapTVar
          . HashMap.insert newCid cfg
          $ HashMap.delete oldCid m

addCfg :: CfgId -> TypedCfg -> EventLoop ()
addCfg cid cfg = do
  cfgMapTVar <- view #cfgs <$> ask
  liftIO . atomically $ do
    m <- readTVar cfgMapTVar
    case HashMap.lookup cid m of
      Nothing -> do
        cfgTVar <- newTVar cfg
        writeTVar cfgMapTVar $ HashMap.insert cid cfgTVar m
      Just cfgTMVar -> do
        writeTVar cfgTMVar cfg
  return ()

removeCfg :: CfgId -> EventLoop ()
removeCfg cid = do
  cfgMapTVar <- view #cfgs
  liftIO . atomically . modifyTVar cfgMapTVar $ HashMap.delete cid

getCfg :: CfgId -> EventLoop (Maybe TypedCfg)
getCfg cid = do
  cfgMapTVar <- view #cfgs <$> ask
  liftIO . atomically $ do
    m <- readTVar cfgMapTVar
    maybe (return Nothing) (fmap Just . readTVar) $ HashMap.lookup cid m

getRemovedNodes :: Cfg (CfNode ()) -> Cfg (CfNode ()) -> HashSet (CfNode ())
getRemovedNodes old new = HashSet.difference (G.nodes old) (G.nodes new)

getRemovedEdges :: Cfg (CfNode ()) -> Cfg (CfNode ()) -> HashSet (CfEdge (CfNode ()))
getRemovedEdges old new = HashSet.difference (f old) (f new)
  where
    f = HashSet.fromList . fmap Cfg.fromLEdge . G.edges . view #graph

edgeToUUIDTuple :: CfEdge (CfNode a) -> (UUID, UUID)
edgeToUUIDTuple e = (Cfg.getNodeUUID $ e ^. #src, Cfg.getNodeUUID $ e ^. #dst)
