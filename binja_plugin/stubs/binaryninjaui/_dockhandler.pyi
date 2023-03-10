#!/usr/bin/env python3

from typing import Callable, overload

from binaryninja import BinaryView
from binaryninja.binaryview import BinaryView
from PySide6.QtCore import QObject, Qt
from PySide6.QtWidgets import QDockWidget, QWidget

from ._viewframe import View, ViewFrame, ViewLocation


class DockContextHandler:
    def __init__(self, widget: QWidget, name: str, /) -> None:
        ...

    def getName(self) -> str:
        ...

    def getParentWindow(self) -> QWidget:
        ...

    def notifyFontChanged(self) -> None:
        ...

    def notifyOffsetChanged(self, offset: int, /) -> None:
        ...

    def notifyThemeChanged(self) -> None:
        ...

    def notifyViewChanged(self, frame: ViewFrame, /) -> None:
        ...

    def notifyViewLocationChanged(self, view: View, viewLocation: ViewLocation, /) -> None:
        ...

    def notifyVisibilityChanged(self, visible: bool, /) -> None:
        ...

    def shouldBeVisible(self, frame: ViewFrame, /) -> bool:
        ...


class DockHandler(QObject):
    def __init__(self, parent: QObject, windowIndex: int, /) -> None:
        ...

    @overload
    def addDockWidget(
        self,
        widget: QWidget,
        area: Qt.DockWidgetArea = Qt.DockWidgetArea.BottomDockWidgetArea,
        orientation: Qt.Orientation = Qt.Orientation.Horizontal,
        defaultVisibility: bool = False,
        /,
    ) -> bool:
        ...

    @overload
    def addDockWidget(
        self,
        name: str,
        createWidget: Callable[[str, ViewFrame, BinaryView], QWidget],
        area: Qt.DockWidgetArea = Qt.DockWidgetArea.BottomDockWidgetArea,
        orientation: Qt.Orientation = Qt.Orientation.Horizontal,
        defaultVisibility: bool = False,
        /,
    ) -> bool:
        ...

    def getDockWidget(self, name: str, /) -> QDockWidget:
        ...

    def getViewFrame(self) -> ViewFrame:
        ...

    @staticmethod
    def getActiveDockHandler() -> DockHandler:
        ...
