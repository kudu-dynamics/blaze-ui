import logging as _logging
from datetime import datetime
from typing import List, TYPE_CHECKING

import binaryninjaui
from binaryninjaui import (
    ContextMenuManager,
    DockContextHandler,
    Menu, 
    UIActionContext,
    UIActionHandler,
    ViewFrame,
)

if getattr(binaryninjaui, 'qt_major_version', None) == 6:
    from PySide6.QtCore import Qt  # type: ignore
    from PySide6.QtGui import QContextMenuEvent, QMouseEvent  # type: ignore
    from PySide6.QtWidgets import QWidget, QListWidget, QListWidgetItem, QVBoxLayout  # type: ignore
else:
    from PySide2.QtCore import Qt  # type: ignore
    from PySide2.QtGui import QContextMenuEvent, QMouseEvent  # type: ignore
    from PySide2.QtWidgets import QWidget, QListWidget, QListWidgetItem, QVBoxLayout  # type: ignore

from .types import MenuOrder
from .util import BNAction, add_actions, bind_actions, try_debug

if TYPE_CHECKING:
    from .client_plugin import BlazeInstance

log = _logging.getLogger(__name__)

class PoiListItem(QListWidgetItem):
    def __init__(
            self,
            parent: QListWidget,
            name: str,
            desc: str,
            func_name: str,
            instr_addr: int,
            created_on: datetime):
        '''
        parent: the parent list widget
        '''
        QListWidgetItem.__init__(
            self,
            parent,  # type: ignore
            type=QListWidgetItem.UserType)

        self.name = name
        self.desc = desc
        self.func_name = func_name
        self.instr_addr = instr_addr
        self.created_on = created_on
        
        self.update_text()

    def update_text(self):
        if self.name:
            item_str = f'{self.name} ({self.func_name} @ 0x{hex(self.instr_addr)})'
            self.setText(item_str)
        else:
            item_str = f'{self.func_name} @ 0x{hex(self.instr_addr)}'
            self.setText(item_str)


class PoiListWidget(QListWidget):
    '''
    A list view for displaying and selecting POIs/destination locations.
    '''
    def __init__(self, parent: QWidget, blaze_instance: 'BlazeInstance'):
        QListWidget.__init__(self, parent)
        self.blaze_instance: 'BlazeInstance' = blaze_instance

        self.action_handler = UIActionHandler()
        self.action_handler.setupActionHandler(self)
        self.context_menu = Menu()
        self.context_menu_manager = ContextMenuManager(self)

        # yapf: disable
        actions: List[BNAction] = [
            BNAction(
                'Blaze', 'Set Active POI', MenuOrder.FIRST,
                activate=self.ctx_menu_action_set_active_poi,
                isValid=lambda ctx: self.clicked_item is not None
            ),
        ]
        #yapf: enable

        bind_actions(self.action_handler, actions)
        add_actions(self.context_menu, actions)

        log.debug('%r initialized', self)

    def __del__(self):
        try_debug(log, 'Deleting %r', self)

    def mousePressEvent(self, event: QMouseEvent) -> None:
        if event.button() != Qt.RightButton:
            return super().mousePressEvent(event)

        ev_pos = event.pos()
        if (item := self.itemAt(ev_pos)):
            self.clicked_item = item
            self.context_menu_manager.show(self.context_menu, self.action_handler)

    def ctx_menu_action_set_active_poi(self, context: UIActionContext) -> None:
        if not self.clicked_item:
            return

        log.debug('Set Active POI action')
        return

class PoiListDockWidget(QWidget, DockContextHandler):
    '''
    Binary Ninja dock widget containing the POI list view.
    '''
    def __init__(
        self, name: str, view_frame: ViewFrame, parent: QWidget, 
        blaze_instance: 'BlazeInstance'):
        QWidget.__init__(self, parent)
        DockContextHandler.__init__(self, self, name)

        self._view_frame: ViewFrame = view_frame
        self.blaze_instance: 'BlazeInstance' = blaze_instance
        self.poi_list_widget = PoiListWidget(self, blaze_instance)

        layout = QVBoxLayout()  # type: ignore
        layout.setContentsMargins(0, 0, 0, 0)  # type: ignore
        layout.setSpacing(0)
        layout.addWidget(self.poi_list_widget)
        self.setLayout(layout)

        log.debug('%r initialized', self)

    def __del__(self):
        try_debug(log, 'Deleting %r', self)