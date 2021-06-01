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
from binaryninja.function import AddressRange, InstructionTextToken, Variable
from binaryninja.highlevelil import HighLevelILFunction
from binaryninja.lineardisassembly import LinearDisassemblyLine, LinearViewCursor
from binaryninja.lowlevelil import LowLevelILFunction
from binaryninja.mediumlevelil import MediumLevelILFunction
from PySide2.QtCore import QObject, QPoint, Qt
from PySide2.QtGui import QKeySequence, QMouseEvent, QWheelEvent
from PySide2.QtWidgets import QAbstractScrollArea, QDockWidget, QMainWindow, QMenu, QWidget
from binaryninja.plugin import PluginCommandContext

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

    def serialize(self) -> dict: ...
    def deserialize(self, value: dict, /) -> bool: ...

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

    @overload
    def __init__(self) -> None: ...
    @overload
    def __init__(self, pluginContext: PluginCommandContext, /) -> None: ...

class UIAction:
    activate: Callable[[UIActionContext], None]
    isValid: Callable[[UIActionContext], bool]

    @overload
    def __init__(self): ...
    @overload
    def __init__(self, activate: Callable[[UIActionContext], None], /): ...
    @overload
    def __init__(self, activate: Callable[[UIActionContext], None], isValid: Callable[[UIActionContext], bool], /): ...
    @overload
    def __init__(self, other: UIAction, /): ...

    @staticmethod
    def registerAction(name: str, defaultKeyBinding: Union[QKeySequence, List[QKeySequence]] = QKeySequence(), /): ...  # type: ignore
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
    def __init__(self, isGlobal: bool = False, /): ...
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

    @overload
    def executeAction(self, name: str, /) -> None: ...
    @overload
    def executeAction(self, name: str, context: UIActionContext, /) -> None: ...

    def isBoundAction(self, name: str, /) -> bool: ...

    @overload
    def isValidAction(self, name: str, /) -> bool: ...
    @overload
    def isValidAction(self, name: str, context: UIActionContext, /) -> bool: ...

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
    def setActionContext(self, contextFunc: Callable[[], UIActionContext], /) -> None: ...

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
    @overload
    def __init__(self): ...
    @overload
    def __init__(self, menu: 'Menu', /): ...

    @overload
    def addAction(self, action: str, group: str, order: Literal[0, 64, 128, 192, 255] = 128, /) -> None:
        '''
        :param: order
            0: MENU_ORDER_FIRST
            64: MENU_ORDER_EARLY
            128: MENU_ORDER_NORMAL
            192: MENU_ORDER_LATE
            255: MENU_ORDER_LAST
        '''

    @overload
    def addAction(self, submenu: str, action: str, group: str, order: Literal[0, 64, 128, 192, 255] = 128, /) -> None:
        '''
        :param: order
            0: MENU_ORDER_FIRST
            64: MENU_ORDER_EARLY
            128: MENU_ORDER_NORMAL
            192: MENU_ORDER_LATE
            255: MENU_ORDER_LAST
        '''

    @overload
    def removeAction(self, action: str, /) -> None: ...
    @overload
    def removeAction(self, submenu: str, action: str, /) -> None: ...

    def setOrdering(self, path: str, group: str, order: int = 128, /) -> None:
        '''
        :param: order
            0: MENU_ORDER_FIRST
            64: MENU_ORDER_EARLY
            128: MENU_ORDER_NORMAL
            192: MENU_ORDER_LATE
            255: MENU_ORDER_LAST
        '''

    def setGroupOrdering(self, group: str, order: int, /) -> None: ...
    def setVisibility(self, path: str, visibility: MenuItemVisibility, /) -> None: ...

    @overload
    def create(self, owner: QWidget, handler: UIActionHandler, showInactiveActions: bool = False, /) -> None: ...
    @overload
    def create(self, owner: QWidget, handler: UIActionHandler, context: UIActionContext, showInactiveActions: bool = False, /) -> None: ...

class MenuInstance:
    def __init__(self, menu: Menu, instance: QMenu, /): ...
    @overload
    def update(self, handler: UIActionHandler, showInactiveActions: bool = False, /) -> None: ...
    @overload
    def update(self, handler: UIActionHandler, context: UIActionContext, showInactiveActions: bool = False, /) -> None: ...

    def source(self) -> Menu: ...
    def instance(self) -> QMenu: ...

    @staticmethod
    def updateActionBindings(name: str, /) -> None: ...


# dockhandler.h

class DockContextHandler:
    def __init__(self, widget: QWidget, name: str, /): ...
    def getName(self) -> str: ...
    def getParentWindow(self) -> QWidget: ...
    def notifyFontChanged(self) -> None: ...
    def notifyOffsetChanged(self, offset: int, /) -> None: ...
    def notifyThemeChanged(self) -> None: ...
    def notifyViewChanged(self, frame: ViewFrame, /) -> None: ...
    def notifyViewLocationChanged(self, view: View, viewLocation: ViewLocation, /) -> None: ...
    def notifyVisibilityChanged(self, visible: bool, /) -> None: ...
    def shouldBeVisible(self, frame: ViewFrame, /) -> bool: ...

class DockHandler(QObject):
    def __init__(self, parent: QObject, windowIndex: int, /): ...

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

    def getDockWidget(self, name: str, /) -> QDockWidget: ...
    def getViewFrame(self) -> ViewFrame: ...

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
        createViews: bool = True,
        /
    ): ...

    def getFilename(self) -> str: ...
    def getCurrentViewFrame(self) -> ViewFrame: ...

    def GetCurrentView(self) -> str: ...
    def GetCurrentOffset(self) -> int: ...
    def Navigate(self, view: str, offset: int, /) -> bool: ...
    def updateAnalysis(self): ...

    @staticmethod
    def newFile() -> FileContext: ...
    @staticmethod
    def openFilename(path: str, /) -> FileContext: ...


# flowgraphwidget.h

TagReference: Type

class FlowGraphWidget(QAbstractScrollArea, View, PreviewScrollHandler, BinaryDataNotification):
    def __init__(self, parent: QWidget, view: BinaryView, graph: FlowGraph = FlowGraph(), /): ...

    def OnAnalysisFunctionUpdated(self, data: BinaryView, func: Function, /) -> None: ...
    def OnAnalysisFunctionUpdateRequested(self, data: BinaryView, func: Function, /) -> None: ...
    def OnDataMetadataUpdated(self, data: BinaryView, offset: int, /) -> None: ...
    def OnTagUpdated(self, data: BinaryView, tagRef: TagReference, /) -> None: ...

    @overload
    def setInitialGraph(self, graph: FlowGraph, /) -> None: ...
    @overload
    def setInitialGraph(self, graph: FlowGraph, addr: int, /) -> None: ...

    @overload
    def setGraph(self, graph: FlowGraph, /): ...
    @overload
    def setGraph(self, graph: FlowGraph, addr: int, /): ...
    @overload
    def setRelatedGraph(self, graph: FlowGraph, /) -> None: ...
    @overload
    def setRelatedGraph(self, graph: FlowGraph, addr: int, /) -> None: ...
    def updateToGraph(self, graph: FlowGraph, /) -> None: ...

    def getData(self) -> BinaryView: ...
    def getCurrentOffset(self) -> int: ...
    def getSelectionOffsets(self) -> AddressRange: ...
    # def getSelectionForXref(self) -> SelectionInfoForXref: ...
    def setSelectionOffsets(self, range: AddressRange, /) -> None: ...
    # virtual bool navigate(uint64_t pos) override;
    # virtual bool navigateToFunction(FunctionRef func, uint64_t pos) override;
    # virtual bool navigateToViewLocation(const ViewLocation& viewLocation) override;
    # bool navigateWithHistoryEntry(uint64_t addr, FlowGraphHistoryEntry* entry);
    # bool navigateWithHistoryEntry(FunctionRef func, uint64_t addr, FlowGraphHistoryEntry* entry);
    # void setNavigationTarget(View* target) { m_navigationTarget = target; }

    # virtual void clearRelatedHighlights();
    # virtual void setRelatedIndexHighlights(const std::set<size_t>& related);
    # virtual void setRelatedInstructionHighlights(const std::set<uint64_t>& related);

    # virtual void zoom(bool direction);
    # virtual void zoomActual();
    # virtual bool event(QEvent* event) override;
    # void disableZoom();
    # virtual void sendWheelEvent(QWheelEvent* event) override;

    # virtual void cut() override;
    # virtual void copy(TransformRef xform) override;
    # virtual void paste(TransformRef xform) override;

    # virtual bool canAssemble() override;
    # virtual bool canCompile() override;
    # virtual bool canPaste() override;

    # virtual void closing() override;

    # virtual HistoryEntry* getHistoryEntry() override;
    # void populateDefaultHistoryEntry(FlowGraphHistoryEntry* entry);
    # virtual void navigateToHistoryEntry(HistoryEntry* entry) override;

    # virtual FunctionRef getCurrentFunction() override;
    # virtual BasicBlockRef getCurrentBasicBlock() override;
    # virtual ArchitectureRef getCurrentArchitecture() override;

    # virtual LowLevelILFunctionRef getCurrentLowLevelILFunction() override;
    # virtual MediumLevelILFunctionRef getCurrentMediumLevelILFunction() override;
    # virtual size_t getCurrentILInstructionIndex() override;

    # void scrollToCursor();
    # bool isUpdating();

    # QFont getFont() override { return m_render.getFont(); }
    # virtual HighlightTokenState getHighlightTokenState() override { return m_highlight; }
    # QRect getMiniRenderRect() const { return m_miniRenderRect; }
    # void paintMiniGraphAndViewport(QWidget* owner);
    # bool paintMiniGraph(QWidget* owner, QPainter& p);

    # void paintNode(QPainter& p, FlowGraphNodeRef& node, int minY, int maxY);
    # void paintHighlight(QPainter& p, const std::vector<BinaryNinja::DisassemblyTextLine>& lines,
    #     int nodeX, int nodeWidth, int x, int y, size_t line, int tagIndent);
    # void paintEdge(QPainter& p, const FlowGraphNodeRef& node, const BinaryNinja::FlowGraphEdge& edge);

    # void showAddress(uint64_t addr, bool select = false);
    # void showIndex(size_t index);
    # void showTopNode();
    def showNode(self, node: FlowGraphNode, /) -> None: ...
    # void showLineInNode(FlowGraphNodeRef node, size_t lineIndex);
    # void ensureCursorVisible();

    # void viewInTypesView(std::string typeName, uint64_t offset = 0);

    # void setInstructionHighlight(BNHighlightColor color);
    # void setBlockHighlight(BNHighlightColor color);

    # virtual bool goToReference(FunctionRef func, uint64_t source, uint64_t target) override;

    # void setHighlightToken(const HighlightTokenState& state, bool notify = true);

    # virtual void notifyUpdateInProgress(FunctionRef func);
    # virtual void onFunctionSelected(FunctionRef func);
    # virtual void onHighlightChanged(const HighlightTokenState& highlight);

    # static std::string getPossibleValueSetStateName(BNRegisterValueType state);
    # static std::string getStringForRegisterValue(ArchitectureRef arch, BinaryNinja::RegisterValue value);
    # static std::string getStringForPossibleValueSet(ArchitectureRef arch, const BinaryNinja::PossibleValueSet& values);

    def getNodeForMouseEvent(self, event: QMouseEvent, /) -> Optional[FlowGraphNode]: ...
    def getEdgeForMouseEvent(self, event: QMouseEvent, /) -> Optional[Tuple[FlowGraphEdge, bool]]:
        '''Returns `None` if no edge was clicked, or `(edge, is_incoming)` if an edge was
        clicked. `is_incoming` is `True` if the edge was clicked near the target of the
        edge, and `False` if it was clicked neat the source of the edge.'''
    # def getLineForMouseEvent(self, event: QMouseEvent, /) -> Optional[Any]: ...
    def getTokenForMouseEvent(self, event: QMouseEvent, /) -> Optional[HighlightTokenState]: ...

# linearview.h

class LinearViewLine(LinearDisassemblyLine):
    cursor: LinearViewCursor
    lineIndex: int

class LinearViewCursorPosition:
    function: Function
    block: BasicBlock
    address: int
    instrIndex: int
    cursor: LinearViewCursor
    lineIndex: int
    tokenIndex: int
    characterIndex: int
    cursorX: int
    cursorY: int

    @overload
    def __init__(self): ...
    @overload
    def __init__(self, pos: 'LinearViewCursorPosition', /): ...
    @overload
    def __init__(self, line: LinearViewLine, /): ...

    def __lt__(self, other: 'LinearViewCursorPosition', /) -> bool: ...
    def __le__(self, other: 'LinearViewCursorPosition', /) -> bool: ...
    def __gt__(self, other: 'LinearViewCursorPosition', /) -> bool: ...
    def __ge__(self, other: 'LinearViewCursorPosition', /) -> bool: ...

    def AsLine(self) -> 'LinearViewCursorPosition': ...


# menus.h

class ContextMenuManager(QObject):
    @overload
    def __init__(self) -> None: ...
    @overload
    def __init__(self, parent: QWidget, /) -> None: ...

    def create(self) -> QMenu: ...

    @overload
    def show(self, view: View, /) -> MenuInstance: ...
    @overload
    def show(self, pos: QPoint, view: View, /) -> MenuInstance: ...
    @overload
    def show(self, source: Menu, handler: UIActionHandler, /) -> MenuInstance: ...
    @overload
    def show(self, pos: QPoint, source: Menu, handler: UIActionHandler, /) -> MenuInstance: ...

    def isActive(self) -> bool: ...


# preview.h

class PreviewScrollHandler:
    def __init__(self): ...
    def sendWheelEvent(self, event: QWheelEvent, /) -> None: ...


# uicontext.h

class UIContextNotification:
    def __init__(self): ...

    def OnContextOpen(self, context: UIContext, /) -> None: ...
    def OnContextClose(self, context: UIContext, /) -> None: ...

    def OnBeforeOpenDatabase(self, context: UIContext, metadata: FileMetadata, /) -> bool: ...
    def OnAfterOpenDatabase(self, context: UIContext, metadata: FileMetadata, data: BinaryView, /) -> bool: ...
    def OnBeforeOpenFile(self, context: UIContext, file: FileContext, /) -> bool: ...
    def OnAfterOpenFile(self, context: UIContext, file: FileContext, frame: ViewFrame, /) -> None: ...
    def OnBeforeSaveFile(self, context: UIContext, file: FileContext, frame: ViewFrame, /) -> bool: ...
    def OnAfterSaveFile(self, context: UIContext, file: FileContext, frame: ViewFrame, /) -> None: ...
    def OnBeforeCloseFile(self, context: UIContext, file: FileContext, frame: ViewFrame, /) -> bool: ...
    def OnAfterCloseFile(self, context: UIContext, file: FileContext, frame: ViewFrame, /) -> None: ...

    def OnViewChange(self, context: UIContext, frame: ViewFrame, type: str, /) -> None: ...
    def OnAddressChange(self, context: UIContext, frame: ViewFrame, view: View, location: ViewLocation, /) -> None: ...

class UIContext():
    def __init__(self): ...

    def mainWindow(self) -> QMainWindow: ...
    def viewChanged(self, frame: ViewFrame, type: str, /) -> None: ...
    def navigateForBinaryView(self, view: BinaryView, addr: int, /) -> bool: ...

    def getCurrentView(self) -> View: ...
    def getCurrentViewFrame(self) -> ViewFrame: ...
    def getCurrentActionHandler(self) -> UIActionHandler: ...

    def createTabForWidget(self, name: str, widget: QWidget, /) -> None: ...
    def getTabs(self) -> List[QWidget]: ...
    def getTabForName(self, name: str, /) -> QWidget: ...
    def openFilename(self, path: str, openOptions: bool = False, /) -> bool: ...
    def openFileContext(self, file: FileContext, forcedView: str = '', addTab: bool = True, /) -> ViewFrame: ...


    @staticmethod
    def registerNotification(notification: UIContextNotification, /) -> None: ...
    @staticmethod
    def unregisterNotification(notification: UIContextNotification, /) -> None: ...

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
    def __init__(self, parent: QWidget, file: FileContext, type: str, createDynamicWidgets: bool = False, /): ...
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
    def navigate(self, type: str, offset: int, updateInfo: bool = True, addHistoryEntry: bool = True, /) -> bool: ...
    # @overload
    # bool navigate(const QString& type, const std::function<bool(View*)>& handler, bool updateInfo = true, bool addHistoryEntry = true);
    @overload
    def navigate(self, data: BinaryView, offset: int, updateInfo: bool = True, addHistoryEntry: bool = True, /) -> bool: ...
    def navigateToFunction(self, func: Function, offset: int, updateInfo: bool = True, addHistoryEntry: bool = True, /) -> bool: ...
    def goToReference(self, data: BinaryView, func: Function, source: int, target: int, addHistoryEntry: bool = True, /) -> bool: ...

    def getTypeForView(self, view: QWidget, /) -> str: ...
    @overload
    def getDataTypeForView(self, type: str, /) -> str: ...
    @overload
    def getDataTypeForView(self, view: QWidget, /) -> str: ...

    def closeRequest(self) -> bool: ...
    def closing(self) -> None: ...

    def setCurrentFunction(self, func: Function, /) -> None: ...
    @staticmethod
    def getDisassemblyText(lines: List[DisassemblyTextLine]) -> str: ...
