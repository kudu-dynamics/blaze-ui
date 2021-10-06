#!/usr/bin/env python3

from PySide6.QtGui import QWheelEvent


class PreviewScrollHandler:
    def __init__(self) -> None:
        ...

    def sendWheelEvent(self, event: QWheelEvent, /) -> None:
        ...
