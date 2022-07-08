import logging as _logging
from typing import TYPE_CHECKING, List, Optional, cast

from binaryninja import (HighlightColor)
from binaryninjaui import (
    ContextMenuManager,
    DockContextHandler,
    Menu,
    UIActionHandler,
    ViewFrame,
)
from PySide6.QtCore import QPoint
from PySide6.QtGui import QMouseEvent
from PySide6.QtWidgets import QListWidget, QListWidgetItem, QVBoxLayout, QWidget

from . import colors
from .types import StmtIndex, TypeError, tokens_to_str
from .util import (
    try_debug,
)

if TYPE_CHECKING:
    from .client_plugin import BlazeInstance

log = _logging.getLogger(__name__)


class TypeErrorListItem(QListWidgetItem):
    def __init__(
        self,
        parent: QListWidget,
        type_error: TypeError,
    ):
        """
        parent: the parent list widget
        """
        QListWidgetItem.__init__(self, parent, type=cast(int, QListWidgetItem.UserType))

        self.parent = parent
        self.stmtOrigin = type_error['stmtOrigin']
        self.sym = type_error['sym']
        self.error = type_error['error']

        self.update_text()

    def update_text(self):
        self.setText(tokens_to_str(self.error))


class TypeErrorListWidget(QListWidget):
    """
    A list view for displaying and selecting type errors in the ICFG.
    """
    def __init__(self, parent: QWidget, blaze_instance: 'BlazeInstance'):
        QListWidget.__init__(self, parent)
        self.blaze_instance: 'BlazeInstance' = blaze_instance

        self.action_handler = UIActionHandler()
        self.action_handler.setupActionHandler(self)
        self.context_menu = Menu()
        self.context_menu_manager = ContextMenuManager(self)

        self.clicked_item: Optional[TypeErrorListItem] = None

        log.debug('Initialized object: %r', self)

    def __del__(self):
        try_debug(log, 'Deleting object: %r', self)


    def highlight_stmt(self, stmt: StmtIndex, color: HighlightColor) -> None:
        if (graph := self.blaze_instance.graph) is not None:
            lines = graph.get_lines_at_index(stmt)
            if lines == []:
                log.warn(f'Cannot find statement corresponding to this type error at StmtIndex {stmt}')
            else:
                for (node, line, line_index) in lines:
                    line.highlight = color
                    assert self.blaze_instance._icfg_dock_widget
                    self.blaze_instance._icfg_dock_widget.icfg_widget.recenter_node_id = graph.node_mapping[node]['contents']['uuid']
                    node.lines = node.lines[0:line_index] + [line] + node.lines[line_index+1:len(node.lines)]                    
                    self.blaze_instance._icfg_dock_widget.set_graph(graph)            
        return None


    def mouseDoubleClickEvent(self, event: QMouseEvent) -> None:
        ev_pos: QPoint = event.pos()
        if (item := self.itemAt(ev_pos)):
            item = cast(TypeErrorListItem, item)
            if self.clicked_item != None:
                self.highlight_stmt(self.clicked_item.stmtOrigin, HighlightColor(None))
            self.highlight_stmt(item.stmtOrigin, colors.TYPE_ERROR_STMT)
            self.clicked_item = item


    def notifyInstanceChanged(self, blaze_instance: 'BlazeInstance', _view_frame: ViewFrame):
        self.blaze_instance = blaze_instance

        
class TypeErrorListDockWidget(QWidget, DockContextHandler):
    """
    Binary Ninja dock widget containing the Type Error list view.
    """
    def __init__(
            self, name: str, view_frame: ViewFrame, parent: QWidget,
            blaze_instance: 'BlazeInstance'):
        QWidget.__init__(self, parent)
        DockContextHandler.__init__(self, self, name)

        self._view_frame: ViewFrame = view_frame
        self.blaze_instance: 'BlazeInstance' = blaze_instance
        self.type_error_list_widget = TypeErrorListWidget(self, blaze_instance)
        self.type_errors: List[TypeError]

        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addWidget(self.type_error_list_widget)
        self.setLayout(layout)

        log.debug('Initialized object: %r', self)

    def __del__(self):
        try_debug(log, 'Deleting object: %r', self)

    def create_type_error_list(self, type_errors: List[TypeError]) -> None:
        for type_error in type_errors:
            type_error_item = TypeErrorListItem(
                parent = self.type_error_list_widget,
                type_error = type_error,
            )
            self.type_error_list_widget.addItem(type_error_item)
                
    def notifyViewChanged(self, view_frame: ViewFrame) -> None:
        if view_frame is None:
            log.error('view_frame is None')
        else:
            view = view_frame.getCurrentViewInterface()
            self.blaze_instance = self.blaze_instance.blaze.ensure_instance(view.getData())
            self.type_error_list_widget.notifyInstanceChanged(self.blaze_instance, view_frame)
