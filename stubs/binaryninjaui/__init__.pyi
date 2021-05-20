# Collecting binaryninjaui.so type stubs that we either use or are likely to
# use. Don't take this as complete or canonical. This is a manual translation
# of relevant headers in binaryninja-api/ui/, so if you're getting a type error
# and you don't think you should be, a type sig in this file might be the culprit

import enum
from typing import Callable, List, Literal, Optional, Tuple, Type, Union, overload

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
from binaryninja.basicblock import BasicBlock
from binaryninja.binaryview import BinaryView
from binaryninja.enums import InstructionTextTokenType
from binaryninja.flowgraph import FlowGraphEdge, FlowGraphNode
from binaryninja.function import InstructionTextToken, Variable
from binaryninja.highlevelil import HighLevelILFunction
from binaryninja.lineardisassembly import LinearViewCursor
from binaryninja.lowlevelil import LowLevelILFunction
from binaryninja.mediumlevelil import MediumLevelILFunction
from PySide2.QtCore import QObject, QPoint, Qt
from PySide2.QtGui import QKeySequence, QMouseEvent
from PySide2.QtWidgets import QAbstractScrollArea, QDockWidget, QMenu, QWidget

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

class UIActionContext:
    context: UIContext
    view: View
    widget: QWidget
    token: HighlightTokenState

    binaryView: BinaryView
    address: int
    length: int
    instrIndex: int
    function: Function
    lowLevelILFunction: LowLevelILFunction
    mediumLevelILFunction: MediumLevelILFunction
    highLevelILFunction: HighLevelILFunction
    cursorPosition: LinearViewCursorPosition

class UIAction:
    activate: Callable[[UIActionContext], None]
    isValid: Callable[[UIActionContext], bool]

    @overload
    def __init__(self, activate: Callable[[UIActionContext], None], isValid: Callable[[UIActionContext], bool], /): ...
    @overload
    def __init__(self, other: UIAction, /): ...

    @staticmethod
    def registerAction(name: str, defaultKeyBinding: Union[QKeySequence, List[QKeySequence]] = None, /): ...
    @staticmethod
    def unregisterAction(name: str, /): ...

    # static void registerTransformActions();
    # static void registerPluginCommandActions();
    # static void registerPluginCommandActions(const QString& prefix);
    # static void registerHighlightColorActions(const QString& prefix);
    # static void registerBookmarkActions(const QString& prefix);

    # static void setActionDisplayName(const QString& registeredName, const QString& displayName);
    # static void setActionDisplayName(const QString& registeredName, const std::function<QString()>& displayNameFunc);
    # static void setActionDisplayName(const QString& registeredName, const std::function<QString(const UIActionContext&)>& displayNameFunc);

    # static bool isActionRegistered(const QString& name);
    # static std::set<QString> getAllRegisteredActions();
    # static QList<QKeySequence> getDefaultKeyBinding(const QString& name);
    # static QList<QKeySequence> getKeyBinding(const QString& name);
    # static QString getActionDisplayName(const QString& name, const UIActionContext& context);

    # static int rawControl();
    # static int rawMeta();

    # static void setUserKeyBinding(const QString& name, const QList<QKeySequence>& keyBinding);
    # static void resetKeyBindingToDefault(const QString& name);
    # static void readKeyBindingsFile();
    # static void writeKeyBindingsFile();

class ActionPriority(enum.Enum):
    LowActionPriority = enum.auto()
    NormalActionPriority = enum.auto()
    HighActionPriority = enum.auto()

class UIActionHandler:
    def __init__(self, isGlobal: bool = False): ...
    def setupActionHandler(self, obj: QWidget, inheritParentBindings: bool = True, /) -> None: ...

    @staticmethod
    def actionHandlerFromWidget(widget: QWidget, /) -> UIActionHandler: ...
    @staticmethod
    def globalActions() -> UIActionHandler: ...

    @overload
    def bindAction(self, name: str, action: UIAction, /) -> None: ...
    @overload
    def bindAction(self, name: str, action: UIAction, priority: ActionPriority, /) -> None: ...

    def unbindAction(self, name: str, /) -> None: ...
    def executeAction(self, name: str, context: UIActionContext = None, /) -> None: ...
    def isBoundAction(self, name: str, /) -> bool: ...
    def isValidAction(self, name: str, context: UIActionContext = None, /) -> bool: ...
    def getPriority(self, name: str, /) -> ActionPriority: ...

    # void bindCopyAsActions(const UITransformAction& action);
    # void bindPasteFromActions(const UITransformAction& action);
    # void bindTransformActions(const UITransformAction& encode, const UITransformAction& decode);
    # void unbindCopyAsActions();
    # void unbindPasteFromActions();
    # void unbindTransformActions();

    # void bindPluginCommandActions();
    # void bindPluginCommandActions(const QString& prefix,
    #     const std::function<UIActionContext(const UIActionContext&, const BinaryNinja::PluginCommand&)>& context,
    #     const std::function<bool(const UIActionContext&, const BinaryNinja::PluginCommand&)>& isValid);
    # void unbindPluginCommandActions();
    # void unbindPluginCommandActions(const QString& prefix);

    # void bindHighlightColorActions(const QString& prefix, const UIHighlightColorAction& action);
    # void unbindHighlightColorActions(const QString& prefix);

    # void bindBookmarkActions(const QString& prefix, const UIBookmarkAction& action);
    # void unbindBookmarkActions(const QString& prefix);

    # void setActionDisplayName(const QString& registeredName, const QString& displayName);
    # void setActionDisplayName(const QString& registeredName, const std::function<QString()>& displayNameFunc);
    # void setActionDisplayName(const QString& registeredName, const std::function<QString(const UIActionContext&)>& displayNameFunc);
    # QString getActionDisplayName(const QString& name);
    # QString getActionDisplayName(const QString& name, const UIActionContext& context);

    # void setChecked(const QString& name, bool checked);
    # void setChecked(const QString& name, const std::function<bool()>& checked);
    # void setChecked(const QString& name, const std::function<bool(const UIActionContext&)>& checked);
    # bool isChecked(const QString& name);
    # bool isChecked(const QString& name, const UIActionContext& context);
    # bool isCheckable(const QString& name);

    # std::set<QString> getAllValidActions();
    # std::set<QString> getAllValidActions(const UIActionContext& context);

    def defaultActionContext(self) -> UIActionContext: ...
    def actionContext(self) -> UIActionContext: ...
    def setActionContext(self, contextFunc: Callable[[], UIActionContext]) -> None: ...

    def widget(self) -> QWidget: ...

    # static void updateActionBindings(const QString& name);
    # static bool isActionBoundToAnyHandler(const QString& name);
    # static void addGlobalMenuAction(const QString& name);
    # static void removeGlobalMenuAction(const QString& name);

    # static void reparentWidget(QWidget* widget);


class MenuItemVisibility(enum.Enum):
    DefaultMenuItemVisibility = enum.auto()
    DefaultMenuItemVisibility = enum.auto()
    DefaultMenuItemVisibility = enum.auto()
    DefaultMenuItemVisibility = enum.auto()

class Menu:
    def __init__(self, menu: Menu = None): ...

    @overload
    def addAction(self, action: str, group: str, order: Literal[0, 64, 128, 192, 255] = 0) -> None:
        '''
        :param: order
            0: MENU_ORDER_FIRST
            64: MENU_ORDER_EARLY
            128: MENU_ORDER_NORMAL
            192: MENU_ORDER_LATE
            255: MENU_ORDER_LAST
        '''

    @overload
    def addAction(self, submenu: str, action: str, group: str, order: Literal[0, 64, 128, 192, 255] = 0) -> None:
        '''
        :param: order
            0: MENU_ORDER_FIRST
            64: MENU_ORDER_EARLY
            128: MENU_ORDER_NORMAL
            192: MENU_ORDER_LATE
            255: MENU_ORDER_LAST
        '''

    @overload
    def removeAction(self, action: str) -> None: ...
    @overload
    def removeAction(self, submenu: str, action: str) -> None: ...

    def setOrdering(self, path: str, group: str, order: int = 128) -> None:
        '''
        :param: order
            0: MENU_ORDER_FIRST
            64: MENU_ORDER_EARLY
            128: MENU_ORDER_NORMAL
            192: MENU_ORDER_LATE
            255: MENU_ORDER_LAST
        '''

    def setGroupOrdering(self, group: str, order: int) -> None: ...
    def setVisibility(self, path: str, visibility: MenuItemVisibility) -> None: ...

    @overload
    def create(self, owner: QWidget, handler: UIActionHandler, showInactiveActions: bool = False) -> None: ...
    @overload
    def create(self, owner: QWidget, handler: UIActionHandler, context: UIActionContext, showInactiveActions: bool = False) -> None: ...

class MenuInstance:
    def __init__(self, menu: Menu, instance: QMenu): ...
    @overload
    def update(self, handler: UIActionHandler, showInactiveActions: bool = False) -> None: ...
    @overload
    def update(self, handler: UIActionHandler, context: UIActionContext, showInactiveActions: bool = False) -> None: ...

    def source(self) -> Menu: ...
    def instance(self) -> QMenu: ...

    @staticmethod
    def updateActionBindings(name: str) -> None: ...


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
    def getNodeForMouseEvent(self, event: QMouseEvent) -> Optional[FlowGraphNode]: ...
    def getEdgeForMouseEvent(self, event: QMouseEvent) -> Optional[Tuple[FlowGraphEdge, bool]]:
        '''Returns `None` if no edge was clicked, or `(edge, is_incoming)` if an edge was
        clicked. `is_incoming` is `True` if the edge was clicked near the target of the
        edge, and `False` if it was clicked neat the source of the edge.'''
    # def getLineForMouseEvent(self, event: QMouseEvent) -> Optional[Any]: ...
    def getTokenForMouseEvent(self, event: QMouseEvent) -> Optional[HighlightTokenState]: ...
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


# linearview.h

class LinearViewCursorPosition:
    function: Function
    block: BasicBlock
    address: int
    instrIndex: int
    cursor: LinearViewCursor
    lineIndex: int
    tokenIndex: int


# menus.h

class ContextMenuManager(QObject):
    def __init__(self, parent: QWidget = None) -> None: ...
    def create(self) -> QMenu: ...

    @overload
    def show(self, view: View) -> MenuInstance: ...
    @overload
    def show(self, pos: QPoint, view: View) -> MenuInstance: ...
    @overload
    def show(self, source: Menu, handler: UIActionHandler) -> MenuInstance: ...
    @overload
    def show(self, pos: QPoint, source: Menu, handler: UIActionHandler) -> MenuInstance: ...

    def isActive(self) -> bool: ...


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
