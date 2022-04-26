{-# LANGUAGE ConstraintKinds #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Blaze.UI.Prelude
  ( module Exports
  , writeManyTQueue
  , logLocal
  , logLocalWithTraceback
  , logLocalDebug
  , logLocalInfo
  , logLocalWarning
  , logLocalError
  ) where

import Blaze.Prelude as Exports hiding (SrcLoc)
import Control.Monad.Catch as Exports (MonadMask, MonadCatch, MonadThrow)
import Control.Lens.Extras as Exports (is)
import Control.Concurrent.STM.TQueue as Exports
import Control.Concurrent.STM.TVar as Exports
import Control.Concurrent.STM.TMVar as Exports
import Data.String.Conversions as Exports (ConvertibleStrings)
import Data.Aeson as Exports (ToJSONKey, FromJSONKey)
import Web.Scotty (Parsable(parseParam))
import qualified Data.Text as Text
import Data.Time (getCurrentTime)
import GHC.Stack (SrcLoc(..))
import Data.Time.Format.ISO8601 (iso8601Show)


writeManyTQueue :: TQueue a -> [a] -> STM ()
writeManyTQueue q = mapM_ $ writeTQueue q

instance Parsable Bytes where
  parseParam s = case readMaybe s of
    Nothing -> Left $ "Not a number: " <> s
    Just n -> Right $ Bytes n

instance Parsable Address where
  parseParam s = Address <$> parseParam s

getPrettySrcLoc :: CallStack -> Maybe Text
getPrettySrcLoc callStack' = do
  (funcName, callerLoc) <- atMay (getCallStack callStack') 1
  let SrcLoc {srcLocModule, srcLocStartLine, srcLocStartCol, srcLocEndLine, srcLocEndCol} = callerLoc
      pos = if srcLocStartLine == srcLocEndLine then
              if srcLocStartCol == srcLocEndCol then
                show srcLocStartLine <> ":" <> show srcLocStartCol
              else
                show srcLocStartLine <> ":" <> show srcLocStartCol <> "-" <> show srcLocEndCol
            else
                show srcLocStartLine <> "-" <> show srcLocEndLine
  Just $ Text.concat [cs srcLocModule, ":", cs funcName, ":", pos]

logLocal :: (HasCallStack, MonadIO m) => Text -> Text -> m ()
logLocal level s = do
  time <- cs . iso8601Show <$> liftIO getCurrentTime
  tid <- show <$> liftIO myThreadId
  let loc = fromMaybe "no location info" $ getPrettySrcLoc callStack
  putText . cs $ Text.concat [level, " [", time, "] [", loc, "] [", tid, "] ", s]

logLocalWithTraceback :: (HasCallStack, MonadIO m) => Text -> Text -> m ()
logLocalWithTraceback level s = do
  time <- cs . iso8601Show <$> liftIO getCurrentTime
  tid <- show <$> liftIO myThreadId
  let loc = fromMaybe "no location info" $ getPrettySrcLoc callStack
      stack = cs $ prettyCallStack callStack
  putText . cs $ Text.concat [level, " [", time, "] [", loc, "] [", tid, "] ", s, "\n", stack]

logLocalDebug :: (HasCallStack, MonadIO m) => Text -> m ()
logLocalDebug = withFrozenCallStack $ logLocal "DEBUG"

logLocalInfo :: (HasCallStack, MonadIO m) => Text -> m ()
logLocalInfo = withFrozenCallStack $ logLocal "INFO"

logLocalWarning :: (HasCallStack, MonadIO m) => Text -> m ()
logLocalWarning = withFrozenCallStack $ logLocal "WARNING"

logLocalError :: (HasCallStack, MonadIO m) => Text -> m ()
logLocalError = withFrozenCallStack $ logLocalWithTraceback "ERROR"
