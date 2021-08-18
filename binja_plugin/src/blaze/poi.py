import logging as _logging
from datetime import datetime
from typing import List, Optional, TYPE_CHECKING

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

from .types import BinjaToServer, MenuOrder, PoiBinjaToServer, PoiId, PoiServerToBinja
from .util import BNAction, add_actions, bind_actions, servertime_to_clienttime, try_debug

if TYPE_CHECKING:
    from .client_plugin import BlazeInstance

log = _logging.getLogger(__name__)

class PoiListItem(QListWidgetItem):
    def __init__(
            self,
            parent: QListWidget,
            poiId: PoiId,
            name: str,
            desc: str,
            func_name: str,
            instr_addr: int,
            created_on: datetime):
        """
        parent: the parent list widget
        """
        QListWidgetItem.__init__(
            self,
            parent,  # type: ignore
            type=QListWidgetItem.UserType)

        self.poiId = poiId
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
    """
    A list view for displaying and selecting POIs/destination locations.
    """
    def __init__(self, parent: QWidget, blaze_instance: 'BlazeInstance'):
        QListWidget.__init__(self, parent)
        self.blaze_instance: 'BlazeInstance' = blaze_instance

        self.action_handler = UIActionHandler()
        self.action_handler.setupActionHandler(self)
        self.context_menu = Menu()
        self.context_menu_manager = ContextMenuManager(self)

        self.clicked_item: Optional[PoiListItem] = None

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
        if not self.clicked_item or not self.blaze_instance.graph:
            return

        poi_msg = PoiBinjaToServer(
            tag='ActivatePoiSearch',
            poiId=self.clicked_item.poiId,
            cfgId=self.blaze_instance.graph.pil_icfg_id)

        self.blaze_instance.send(BinjaToServer(tag='BSPoi', poiMsg=poi_msg))

    def notifyInstanceChanged(self, blaze_instance: 'BlazeInstance', _view_frame: ViewFrame):
        self.blaze_instance = blaze_instance

        # Load POIs when switching BVs
        poi_msg = PoiBinjaToServer(tag='GetPoisOfBinary')
        self.blaze_instance.send(BinjaToServer(tag='BSPoi', poiMsg=poi_msg))


class PoiListDockWidget(QWidget, DockContextHandler):
    """
    Binary Ninja dock widget containing the POI list view.
    """
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

    def handle_server_msg(self, poi_msg: PoiServerToBinja):
        """
        Handle POI messages from the Blaze server.
        """
        # Clear existing list of POIs
        self.poi_list_widget.clear()

        # The only message currently sent from the server is the list of POIs
        for poi in poi_msg.get('pois'):
            # TODO: Handle cases where function isn't found 
            func = self.blaze_instance.bv.get_function_at(poi.get('funcAddr'))
            if func:
                created_time = datetime.fromisoformat(
                    servertime_to_clienttime(poi.get('created')))
                poi_item = PoiListItem(self.poi_list_widget,
                                        poi.get('poiId'),
                                        poi.get('name', ''),
                                        poi.get('description', ''),
                                        func.name,
                                        poi.get('instrAddr'),
                                        poi.get('created'))
                self.poi_list_widget.addItem(poi_item)
            else:
                log.info('No function found at address 0x%x for %s', 
                            poi.funcAddr, self.blaze_instance.bv)

    def notifyViewChanged(self, view_frame: ViewFrame) -> None:
        if view_frame is None:
            log.error('view_frame is None')
        else:
            view = view_frame.getCurrentViewInterface()
            self.blaze_instance = self.blaze_instance.blaze.ensure_instance(view.getData())
            self.poi_list_widget.notifyInstanceChanged(self.blaze_instance, view_frame)