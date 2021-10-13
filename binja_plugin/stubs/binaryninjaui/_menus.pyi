#!/usr/bin/env python3

from typing import overload

from PySide6.QtCore import QObject, QPoint
from PySide6.QtWidgets import QMenu, QWidget

from ._action import Menu, MenuInstance, UIActionHandler
from ._viewframe import View


class ContextMenuManager(QObject):
    @overload
    def __init__(self) -> None:
        ...

    @overload
    def __init__(self, parent: QWidget, /) -> None:
        ...

    def create(self) -> QMenu:
        ...

    @overload
    def show(self, view: View, /) -> MenuInstance:
        ...

    @overload
    def show(self, pos: QPoint, view: View, /) -> MenuInstance:
        ...

    @overload
    def show(self, source: Menu, handler: UIActionHandler, /) -> MenuInstance:
        ...

    @overload
    def show(self, pos: QPoint, source: Menu, handler: UIActionHandler, /) -> MenuInstance:
        ...

    def isActive(self) -> bool:
        ...
