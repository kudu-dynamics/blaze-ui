import enum
from typing import Any, Callable, Dict, List, Literal, Optional, Union, overload

from binaryninja import BinaryView, Function
from binaryninja.architecture import Architecture
from binaryninja.binaryview import BinaryView
from binaryninja.enums import InstructionTextTokenType
from binaryninja.function import InstructionTextToken, Variable
from binaryninja.highlevelil import HighLevelILFunction
from binaryninja.lowlevelil import LowLevelILFunction
from binaryninja.mediumlevelil import MediumLevelILFunction
from binaryninja.plugin import PluginCommandContext
from PySide6.QtGui import QKeySequence
from PySide6.QtWidgets import QMenu, QWidget

from ._linearview import LinearViewCursorPosition
from ._uicontext import UIContext
from ._viewframe import View


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

    def __init__(self) -> None:
        ...

    def serialize(self) -> Dict[str, Any]:
        ...

    def deserialize(self, value: Dict[str, Any], /) -> bool:
        ...


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
    def __init__(self) -> None:
        ...

    @overload
    def __init__(self, pluginContext: PluginCommandContext, /) -> None:
        ...


class UIAction:
    activate: Callable[[UIActionContext], None]
    isValid: Callable[[UIActionContext], bool]

    @overload
    def __init__(self) -> None:
        ...

    @overload
    def __init__(self, activate: Callable[[UIActionContext], None], /) -> None:
        ...

    @overload
    def __init__(
        self,
        activate: Callable[[UIActionContext], None],
        isValid: Callable[[UIActionContext], bool],
        /,
    ) -> None:
        ...

    @overload
    def __init__(self, other: UIAction, /) -> None:
        ...

    @staticmethod
    def registerAction(
            name: str,
            defaultKeyBinding: Union[QKeySequence, List[QKeySequence]] = QKeySequence(),
            /,
    ) -> None:
        ...  # type: ignore

    @staticmethod
    def unregisterAction(name: str, /) -> None:
        ...

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
    def __init__(self, isGlobal: bool = False, /) -> None:
        ...

    def setupActionHandler(self, obj: QWidget, inheritParentBindings: bool = True, /) -> None:
        ...

    @staticmethod
    def actionHandlerFromWidget(widget: QWidget, /) -> UIActionHandler:
        ...

    @staticmethod
    def globalActions() -> UIActionHandler:
        ...

    @overload
    def bindAction(self, name: str, action: UIAction, /) -> None:
        ...

    @overload
    def bindAction(self, name: str, action: UIAction, priority: ActionPriority, /) -> None:
        ...

    def unbindAction(self, name: str, /) -> None:
        ...

    @overload
    def executeAction(self, name: str, /) -> None:
        ...

    @overload
    def executeAction(self, name: str, context: UIActionContext, /) -> None:
        ...

    def isBoundAction(self, name: str, /) -> bool:
        ...

    @overload
    def isValidAction(self, name: str, /) -> bool:
        ...

    @overload
    def isValidAction(self, name: str, context: UIActionContext, /) -> bool:
        ...

    def getPriority(self, name: str, /) -> ActionPriority:
        ...

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

    def defaultActionContext(self) -> UIActionContext:
        ...

    def actionContext(self) -> UIActionContext:
        ...

    def setActionContext(self, contextFunc: Callable[[], UIActionContext], /) -> None:
        ...

    def widget(self) -> QWidget:
        ...

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
    def __init__(self) -> None:
        ...

    @overload
    def __init__(self, menu: 'Menu', /) -> None:
        ...

    @overload
    def addAction(
        self,
        action: str,
        group: str,
        order: Literal[0, 64, 128, 192, 255] = 128,
        /,
    ) -> None:
        '''
        :param: order
            0: MENU_ORDER_FIRST
            64: MENU_ORDER_EARLY
            128: MENU_ORDER_NORMAL
            192: MENU_ORDER_LATE
            255: MENU_ORDER_LAST
        '''

    @overload
    def addAction(
        self,
        submenu: str,
        action: str,
        group: str,
        order: Literal[0, 64, 128, 192, 255] = 128,
        /,
    ) -> None:
        '''
        :param: order
            0: MENU_ORDER_FIRST
            64: MENU_ORDER_EARLY
            128: MENU_ORDER_NORMAL
            192: MENU_ORDER_LATE
            255: MENU_ORDER_LAST
        '''

    @overload
    def removeAction(self, action: str, /) -> None:
        ...

    @overload
    def removeAction(self, submenu: str, action: str, /) -> None:
        ...

    def setOrdering(self, path: str, group: str, order: int = 128, /) -> None:
        '''
        :param: order
            0: MENU_ORDER_FIRST
            64: MENU_ORDER_EARLY
            128: MENU_ORDER_NORMAL
            192: MENU_ORDER_LATE
            255: MENU_ORDER_LAST
        '''

    def setGroupOrdering(self, group: str, order: int, /) -> None:
        ...

    def setVisibility(self, path: str, visibility: MenuItemVisibility, /) -> None:
        ...

    @overload
    def create(
        self,
        owner: QWidget,
        handler: UIActionHandler,
        showInactiveActions: bool = False,
        /,
    ) -> None:
        ...

    @overload
    def create(
        self,
        owner: QWidget,
        handler: UIActionHandler,
        context: UIActionContext,
        showInactiveActions: bool = False,
        /,
    ) -> None:
        ...


class MenuInstance:
    def __init__(self, menu: Menu, instance: QMenu, /) -> None:
        ...

    @overload
    def update(self, handler: UIActionHandler, showInactiveActions: bool = False, /) -> None:
        ...

    @overload
    def update(
        self,
        handler: UIActionHandler,
        context: UIActionContext,
        showInactiveActions: bool = False,
        /,
    ) -> None:
        ...

    def source(self) -> Menu:
        ...

    def instance(self) -> QMenu:
        ...

    @staticmethod
    def updateActionBindings(name: str, /) -> None:
        ...
