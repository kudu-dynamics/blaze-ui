#!/usr/bin/env python3

from typing import List

from binaryninja import BinaryView, FileMetadata
from binaryninja.binaryview import BinaryView
from PySide6.QtWidgets import QMainWindow, QWidget

from ._action import UIActionHandler
from ._filecontext import *
from ._viewframe import View, ViewFrame, ViewLocation


class UIContextNotification:
    def __init__(self) -> None:
        ...

    def OnContextOpen(self, context: UIContext, /) -> None:
        ...

    def OnContextClose(self, context: UIContext, /) -> None:
        ...

    def OnBeforeOpenDatabase(self, context: UIContext, metadata: FileMetadata, /) -> bool:
        ...

    def OnAfterOpenDatabase(
        self,
        context: UIContext,
        metadata: FileMetadata,
        data: BinaryView,
        /,
    ) -> bool:
        ...

    def OnBeforeOpenFile(self, context: UIContext, file: FileContext, /) -> bool:
        ...

    def OnAfterOpenFile(self, context: UIContext, file: FileContext, frame: ViewFrame, /) -> None:
        ...

    def OnBeforeSaveFile(self, context: UIContext, file: FileContext, frame: ViewFrame, /) -> bool:
        ...

    def OnAfterSaveFile(self, context: UIContext, file: FileContext, frame: ViewFrame, /) -> None:
        ...

    def OnBeforeCloseFile(self, context: UIContext, file: FileContext, frame: ViewFrame, /) -> bool:
        ...

    def OnAfterCloseFile(self, context: UIContext, file: FileContext, frame: ViewFrame, /) -> None:
        ...

    def OnViewChange(self, context: UIContext, frame: ViewFrame, type: str, /) -> None:
        ...

    def OnAddressChange(
        self,
        context: UIContext,
        frame: ViewFrame,
        view: View,
        location: ViewLocation,
        /,
    ) -> None:
        ...


class UIContext():
    def __init__(self) -> None:
        ...

    def mainWindow(self) -> QMainWindow:
        ...

    def viewChanged(self, frame: ViewFrame, type: str, /) -> None:
        ...

    def navigateForBinaryView(self, view: BinaryView, addr: int, /) -> bool:
        ...

    def getCurrentView(self) -> View:
        ...

    def getCurrentViewFrame(self) -> ViewFrame:
        ...

    def getCurrentActionHandler(self) -> UIActionHandler:
        ...

    def createTabForWidget(self, name: str, widget: QWidget, /) -> None:
        ...

    def getTabs(self) -> List[QWidget]:
        ...

    def getTabForName(self, name: str, /) -> QWidget:
        ...

    def openFilename(self, path: str, openOptions: bool = False, /) -> bool:
        ...

    def openFileContext(
        self,
        file: FileContext,
        forcedView: str = '',
        addTab: bool = True,
        /,
    ) -> ViewFrame:
        ...

    @staticmethod
    def registerNotification(notification: UIContextNotification, /) -> None:
        ...

    @staticmethod
    def unregisterNotification(notification: UIContextNotification, /) -> None:
        ...

    @staticmethod
    def activeContext() -> UIContext:
        ...
