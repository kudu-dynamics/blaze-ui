import logging as _logging
from datetime import datetime
from typing import TYPE_CHECKING, List, Optional, cast

from binaryninja import ( Function )
from binaryninjaui import (
    ContextMenuManager,
    DockContextHandler,
    Menu,
    UIActionContext,
    UIActionHandler,
    ViewFrame,
)
from PySide6.QtCore import QPoint, Qt
from PySide6.QtGui import QMouseEvent
from PySide6.QtWidgets import QListWidget, QListWidgetItem, QVBoxLayout, QWidget

from . import colors
from .types import BinjaToServer, PoiBinjaToServer, PoiId, PoiServerToBinja, Poi
from .util import (
    BNAction,
    add_actions,
    bind_actions,
    get_function_at,
    servertime_to_clienttime,
    try_debug,
)

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
        func: Function,
        instr_addr: int,
        created_on: datetime,
        is_global: bool,
    ):
        """
        parent: the parent list widget
        """
        QListWidgetItem.__init__(self, parent, type=cast(int, QListWidgetItem.UserType))

        self.poiId = poiId
        self.name = name
        self.desc = desc
        self.func = func
        self.instr_addr = instr_addr
        self.created_on = created_on
        self.is_global = is_global

        self.update_text()

    def update_text(self):
        if self.name:
            item_str = f'{self.name} ({self.func.name} @ 0x{hex(self.instr_addr)})'
        else:
            item_str = f'{self.func.name} @ 0x{hex(self.instr_addr)}'

        if self.desc:
            item_str = item_str + f' :: {self.desc}'

        if self.is_global:
            item_str = '* ' + item_str

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

        actions: List[BNAction] = [
            BNAction(
                'Blaze',
                'Set Active POI',
                activate=self.ctx_menu_action_set_active_poi,
                is_valid=lambda ctx: self.clicked_item is not None,
            ),
            BNAction(
                'Blaze',
                'Goto POI',
                activate=self.ctx_menu_action_goto_poi,
                is_valid=lambda ctx: self.clicked_item is not None,
            ),
        ]

        bind_actions(self.action_handler, actions)
        add_actions(self.context_menu, actions)

        # Load POIs on startup
        poi_msg = PoiBinjaToServer(tag='GetPoisOfBinary')
        self.blaze_instance.send(BinjaToServer(tag='BSPoi', poiMsg=poi_msg))

        log.debug('Initialized object: %r', self)

    def __del__(self):
        try_debug(log, 'Deleting object: %r', self)

    def mouseDoubleClickEvent(self, event: QMouseEvent) -> None:
        if event.button() != Qt.LeftButton:
            return super().mousePressEvent(event)

        ev_pos: QPoint = event.pos()
        if (item := self.itemAt(ev_pos)):
            item = cast(PoiListItem, item)
            self.clicked_item = item
            self.set_active_poi(item.poiId)

    def mousePressEvent(self, event: QMouseEvent) -> None:
        if event.button() != Qt.RightButton:
            return super().mousePressEvent(event)

        ev_pos: QPoint = event.pos()
        if (item := self.itemAt(ev_pos)):
            item = cast(PoiListItem, item)
            self.clicked_item = item
            self.context_menu_manager.show(self.context_menu, self.action_handler)

    def set_active_poi(self, poiId: PoiId) -> None:
        if not self.clicked_item:
            return

        active_icfg_id = self.blaze_instance.graph.pil_icfg_id if self.blaze_instance.graph else None

        poi_msg = PoiBinjaToServer(
            tag='ActivatePoiSearch',
            poiId=self.clicked_item.poiId,
            activeCfg=active_icfg_id)

        self.blaze_instance.send(BinjaToServer(tag='BSPoi', poiMsg=poi_msg))

    def ctx_menu_action_set_active_poi(self, context: UIActionContext) -> None:
        if not self.clicked_item:
            return

        self.set_active_poi(self.clicked_item.poiId)

    def ctx_menu_action_goto_poi(self, context: UIActionContext) -> None:
        if not self.clicked_item:
            return
        bv = self.blaze_instance.bv
        highlight = colors.POI
        self.clicked_item.func.set_auto_instr_highlight(self.clicked_item.instr_addr, highlight)
        bv.navigate(bv.view, self.clicked_item.instr_addr)

    def notifyInstanceChanged(self, blaze_instance: 'BlazeInstance', _view_frame: ViewFrame):
        self.blaze_instance = blaze_instance


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
        self.local_pois: List[Poi] = []
        self.global_pois: List[Poi] = []

        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addWidget(self.poi_list_widget)
        self.setLayout(layout)

        log.debug('Initialized object: %r', self)

    def __del__(self):
        try_debug(log, 'Deleting object: %r', self)

    def add_poi_list_item(self, poi: Poi) -> None:
        # TODO: Handle cases where function isn't found
        func = get_function_at(self.blaze_instance.bv, poi['funcAddr'])
        if func:
            created_time = datetime.fromisoformat(servertime_to_clienttime(poi['created']))
            poi_item = PoiListItem(
                parent = self.poi_list_widget,
                poiId = poi['poiId'],
                name = poi['name'] or '',
                desc = poi['description'] or '',
                func = func,
                instr_addr = poi['instrAddr'],
                created_on = created_time,
                is_global = poi['isGlobalPoi'],
            )
            self.poi_list_widget.addItem(poi_item)
        else:
            log.info(
                'No function found at address 0x%x for %s', poi['funcAddr'],
                self.blaze_instance.bv)

    def handle_server_msg(self, poi_msg: PoiServerToBinja):
        """
        Handle POI messages from the Blaze server.
        """
        tag = poi_msg['tag']

        if tag == 'PoisOfBinary':
            pois = cast(List[Poi], poi_msg.get('pois'))
            self.local_pois = pois

        elif tag == 'GlobalPoisOfBinary':
            global_pois = cast(List[Poi], poi_msg.get('globalPois'))
            self.global_pois = global_pois

        # Clear list items
        self.poi_list_widget.clear()

        # Redraw POI list
        for poi in (self.local_pois + self.global_pois):
            self.add_poi_list_item(poi)

    def notifyViewChanged(self, view_frame: ViewFrame) -> None:
        if view_frame is None:
            log.error('view_frame is None')
        else:
            view = view_frame.getCurrentViewInterface()
            self.blaze_instance = self.blaze_instance.blaze.ensure_instance(view.getData())
            self.poi_list_widget.notifyInstanceChanged(self.blaze_instance, view_frame)
