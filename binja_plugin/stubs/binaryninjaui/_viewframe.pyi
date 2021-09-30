from typing import List, overload

from binaryninja import AddressRange, BinaryView, DisassemblyTextLine, Function, FunctionGraphType
from binaryninja.binaryview import BinaryView
from binaryninja.function import AddressRange
from PySide6.QtWidgets import QWidget

from ._dockhandler import DockHandler
from ._filecontext import *


class View:
    def __init__(self) -> None:
        ...

    def getData(self) -> BinaryView:
        ...


class ViewLocation:
    def __init__(self) -> None:
        ...

    def isValid(self) -> bool:
        ...

    def getViewType(self) -> str:
        ...

    def getOffset(self) -> int:
        ...

    def getILViewType(self) -> FunctionGraphType:
        ...

    def getInstrIndex(self) -> int:
        ...

    def getFunction(self) -> Function:
        ...


class ViewFrame(QWidget):
    def __init__(
        self,
        parent: QWidget,
        file: FileContext,
        type: str,
        createDynamicWidgets: bool = False,
        /,
    ) -> None:
        ...

    def getFileContext(self) -> FileContext:
        ...

    def getDockHandler(self) -> DockHandler:
        ...

    def getTabName(self) -> str:
        ...

    def getShortFileName(self) -> str:
        ...

    def getCurrentView(self) -> str:
        ...

    def getCurrentDataType(self) -> str:
        ...

    def getCurrentOffset(self) -> int:
        ...

    def getSelectionOffsets(self) -> AddressRange:
        ...

    def getViewLocation(self) -> ViewLocation:
        ...

    def getCurrentViewInterface(self) -> View:
        ...

    def getCurrentWidget(self) -> QWidget:
        ...

    def focus(self) -> None:
        ...

    @overload
    def navigate(
        self,
        type: str,
        offset: int,
        updateInfo: bool = True,
        addHistoryEntry: bool = True,
        /,
    ) -> bool:
        ...

    # @overload
    # bool navigate(const QString& type, const std::function<bool(View*)>& handler, bool updateInfo = true, bool addHistoryEntry = true);
    @overload
    def navigate(
        self,
        data: BinaryView,
        offset: int,
        updateInfo: bool = True,
        addHistoryEntry: bool = True,
        /,
    ) -> bool:
        ...

    def navigateToFunction(
        self,
        func: Function,
        offset: int,
        updateInfo: bool = True,
        addHistoryEntry: bool = True,
        /,
    ) -> bool:
        ...

    def goToReference(
        self,
        data: BinaryView,
        func: Function,
        source: int,
        target: int,
        addHistoryEntry: bool = True,
        /,
    ) -> bool:
        ...

    def getTypeForView(self, view: QWidget, /) -> str:
        ...

    @overload
    def getDataTypeForView(self, type: str, /) -> str:
        ...

    @overload
    def getDataTypeForView(self, view: QWidget, /) -> str:
        ...

    def closeRequest(self) -> bool:
        ...

    def closing(self) -> None:
        ...

    def setCurrentFunction(self, func: Function, /) -> None:
        ...

    @staticmethod
    def getDisassemblyText(lines: List[DisassemblyTextLine]) -> str:
        ...
