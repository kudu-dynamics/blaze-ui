# Collecting binaryninjaui.so type stubs that we either use or are likely to
# use. Don't take this as complete or canonical. This is a manual translation
# of relevant headers in binaryninja-api/ui/, so if you're getting a type error
# and you don't think you should be, a type sig in this file might be the culprit

from typing import Callable, List, Optional, Type, overload

from binaryninja import (
    AddressRange,
    BinaryDataNotification,
    BinaryView,
    DisassemblyTextLine,
    FileMetadata,
    FlowGraph,
    Function,
    FunctionGraphType,
)
from binaryninja.architecture import Architecture
from binaryninja.enums import InstructionTextTokenType
from binaryninja.function import InstructionTextToken, Variable
from PySide2.QtCore import QObject, Qt
from PySide2.QtGui import QMouseEvent
from PySide2.QtWidgets import QAbstractScrollArea, QDockWidget, QWidget

# action.h

class HighlightTokenState:
    valid: bool
    secondaryHighlight: bool
    type: InstructionTextTokenType
    token: InstructionTextToken
    arch: Optional[Architecture]
    addrValid: bool
    localVarValid: bool
    isDest: bool
    addr: int
    localVar: Variable
    tokenIndex: int
    characterIndex: int

    def __init__(self) -> None: ...


# dockhandler.h

class DockContextHandler:
    def __init__(self, widget: QWidget, name: str): ...
    def getName(self) -> str: ...
    def getParentWindow(self) -> QWidget: ...
    def notifyFontChanged(self) -> None: ...
    def notifyOffsetChanged(self, offset: int) -> None: ...
    def notifyThemeChanged(self) -> None: ...
    def notifyViewChanged(self, frame: ViewFrame) -> None: ...
    def notifyViewLocationChanged(self, view: View, viewLocation: ViewLocation) -> None: ...
    def notifyVisibilityChanged(self, visible: bool) -> None: ...
    def shouldBeVisible(self, frame: ViewFrame) -> bool: ...

class DockHandler(QObject):
    def __init__(self, parent: QObject, windowIndex: int): ...
    def getDockWidget(self, name: str) -> QDockWidget: ...
    def getViewFrame(self) -> ViewFrame: ...
    @overload
    def addDockWidget(
        self,
        widget: QWidget,
        area: Qt.DockWidgetArea = Qt.DockWidgetArea.BottomDockWidgetArea,
        orientation: Qt.Orientation = Qt.Orientation.Horizontal,
        defaultVisibility: bool = False
    ) -> bool: ...
    @overload
    def addDockWidget(
        self,
        name: str,
        createWidget: Callable[[str, ViewFrame, BinaryView], QWidget],
        area: Qt.DockWidgetArea = Qt.DockWidgetArea.BottomDockWidgetArea,
        orientation: Qt.Orientation = Qt.Orientation.Horizontal,
        defaultVisibility: bool = False
    ) -> bool: ...

    @staticmethod
    def getActiveDockHandler() -> DockHandler: ...


# filecontext.h

class FileContext:
    def __init__(
        self,
        file: FileMetadata,
        rawData: BinaryView,
        filename: str = '',
        isValidSaveName: bool = False,
        createViews: bool = True
    ): ...
    def getFilename(self) -> str: ...
    def getCurrentViewFrame(self) -> ViewFrame: ...
    def GetCurrentView(self) -> str: ...
    def GetCurrentOffset(self) -> int: ...
    def Navigate(self, view: str, offset: int) -> bool: ...
    def updateAnalysis(self): ...
    @staticmethod
    def newFile() -> FileContext: ...
    @staticmethod
    def openFilename(path: str) -> FileContext: ...


# flowgraphwidget.h

TagReference: Type

class FlowGraphWidget(QAbstractScrollArea, View, PreviewScrollHandler, BinaryDataNotification):
    def __init__(self, parent: QWidget, view: BinaryView, graph: FlowGraph = None): ...
    # def getNodeForMouseEvent(self, event: QMouseEvent, node: FlowGraphNode) -> bool: ...
    # def getLineForMouseEvent(self, event: QMouseEvent, node: CursorPosition) -> bool: ...
    # def getLineForMouseEvent(self, event: QMouseEvent, node: CursorPosition) -> bool: ...
    def getTokenForMouseEvent(self, event: QMouseEvent) -> HighlightTokenState: ...
    def OnAnalysisFunctionUpdated(self, data: BinaryView, func: Function) -> None: ...
    def OnAnalysisFunctionUpdateRequested(self, data: BinaryView, func: Function) -> None: ...
    def OnDataMetadataUpdated(self, data: BinaryView, offset: int) -> None: ...
    def OnTagUpdated(self, data: BinaryView, tagRef: TagReference) -> None: ...
    @overload
    def setInitialGraph(self, graph: FlowGraph) -> None: ...
    @overload
    def setInitialGraph(self, graph: FlowGraph, addr: int) -> None: ...
    @overload
    def setGraph(self, graph: FlowGraph): ...
    @overload
    def setGraph(self, graph: FlowGraph, addr: int): ...
    @overload
    def setRelatedGraph(self, graph: FlowGraph) -> None: ...
    @overload
    def setRelatedGraph(self, graph: FlowGraph, addr: int) -> None: ...
    def updateToGraph(self, graph: FlowGraph) -> None: ...


# preview.h

class PreviewScrollHandler:
    def __init__(self): ...


# uicontext.h

class UIContextNotification:
    def __init__(self): ...

    def OnContextOpen(self, context: UIContext) -> None: ...
    def OnContextClose(self, context: UIContext) -> None: ...

    def OnBeforeOpenDatabase(self, context: UIContext, metadata: FileMetadata) -> bool: ...
    def OnAfterOpenDatabase(self, context: UIContext, metadata: FileMetadata, data: BinaryView) -> bool: ...
    def OnBeforeOpenFile(self, context: UIContext, file: FileContext) -> bool: ...
    def OnAfterOpenFile(self, context: UIContext, file: FileContext, frame: ViewFrame) -> None: ...
    def OnBeforeSaveFile(self, context: UIContext, file: FileContext, frame: ViewFrame) -> bool: ...
    def OnAfterSaveFile(self, context: UIContext, file: FileContext, frame: ViewFrame) -> None: ...
    def OnBeforeCloseFile(self, context: UIContext, file: FileContext, frame: ViewFrame) -> bool: ...
    def OnAfterCloseFile(self, context: UIContext, file: FileContext, frame: ViewFrame) -> None: ...

    def OnViewChange(self, context: UIContext, frame: ViewFrame, type: str) -> None: ...
    def OnAddressChange(self, context: UIContext, frame: ViewFrame, view: View, location: ViewLocation) -> None: ...

class UIContext():
    def __init__(self): ...
    def viewChanged(self, frame: ViewFrame, type: str) -> None: ...
    def navigateForBinaryView(self, view: BinaryView, addr: int) -> None: ...
    def createTabForWidget(self, name: str, widget: QWidget) -> None: ...
    def openFilename(self, path: str, openOptions: bool = False) -> bool: ...
    def openFileContext(self, file: FileContext, forcedView: str = '', addTab: bool = True) -> ViewFrame: ...

    @staticmethod
    def registerNotification(notification: UIContextNotification) -> None: ...
    @staticmethod
    def unregisterNotification(notification: UIContextNotification) -> None: ...

    @staticmethod
    def activeContext() -> UIContext: ...


# viewframe.h

class View:
    def __init__(self): ...
    def getData(self) -> BinaryView: ...

class ViewLocation:
    def __init__(self): ...
    def isValid(self) -> bool: ...
    def getViewType(self) -> str: ...
    def getOffset(self) -> int: ...
    def getILViewType(self) -> FunctionGraphType: ...
    def getInstrIndex(self) -> int: ...
    def getFunction(self) -> Function: ...

class ViewFrame(QWidget):
    def __init__(self, parent: QWidget, file: FileContext, type: str, createDynamicWidgets: bool = False): ...
    def getFileContext(self) -> FileContext: ...
    def getDockHandler(self) -> DockHandler: ...
    def getTabName(self) -> str: ...
    def getShortFileName(self) -> str: ...
    def getCurrentView(self) -> str: ...
    def getCurrentDataType(self) -> str: ...
    def getCurrentOffset(self) -> int: ...
    def getSelectionOffsets(self) -> AddressRange: ...
    def getViewLocation(self) -> ViewLocation: ...
    def getCurrentViewInterface(self) -> View: ...
    def getCurrentWidget(self) -> QWidget: ...
    def focus(self) -> None: ...

    @overload
    def navigate(self, type: str, offset: int, updateInfo: bool = True, addHistoryEntry: bool = True) -> bool: ...
    # @overload
    # bool navigate(const QString& type, const std::function<bool(View*)>& handler, bool updateInfo = true, bool addHistoryEntry = true);
    @overload
    def navigate(self, data: BinaryView, offset: int, updateInfo: bool = True, addHistoryEntry: bool = True) -> bool: ...
    def navigateToFunction(self, func: Function, offset: int, updateInfo: bool = True, addHistoryEntry: bool = True) -> bool: ...
    def goToReference(self, data: BinaryView, func: Function, source: int, target: int, addHistoryEntry: bool = True) -> bool: ...

    def getTypeForView(self, view: QWidget) -> str: ...
    @overload
    def getDataTypeForView(self, type: str) -> str: ...
    @overload
    def getDataTypeForView(self, view: QWidget) -> str: ...

    def closeRequest(self) -> bool: ...
    def closing(self) -> None: ...

    def setCurrentFunction(self, func: Function) -> None: ...
    @staticmethod
    def getDisassemblyText(lines: List[DisassemblyTextLine]) -> str: ...
