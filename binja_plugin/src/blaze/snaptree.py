import enum
import logging as _logging
from datetime import datetime
from typing import TYPE_CHECKING, Dict, List, Optional, Set, Tuple, Union, cast

from binaryninja.interaction import TextLineField, get_form_input
from binaryninjaui import (
    ContextMenuManager,
    DockContextHandler,
    Menu,
    UIActionContext,
    UIActionHandler,
    ViewFrame,
)

from PySide6.QtCore import Qt
from PySide6.QtGui import QMouseEvent
from PySide6.QtWidgets import QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget

from .types import (
    Address,
    BinjaToServer,
    Branch,
    BranchId,
    BranchTree,
    BranchTreeListItem,
    CfgId,
    MenuOrder,
    ServerBranch,
    ServerBranchTree,
    SnapshotBinjaToServer,
    SnapshotInfo,
)
from .util import (
    BNAction,
    ITEM_DATE_FMT_OUT,
    add_actions,
    bind_actions,
    servertime_to_clienttime,
    try_debug,
)

if TYPE_CHECKING:
    from .client_plugin import BlazeInstance

log = _logging.getLogger(__name__)

# =================================================================================================


def branch_tree_from_server(branch_tree: ServerBranchTree) -> BranchTree:
    edges = [edge[1] for edge in branch_tree['edges']]
    return BranchTree(edges=edges)


def branch_from_server(branch: ServerBranch) -> Branch:
    updated = {  # type: ignore
        **branch, 'tree': branch_tree_from_server(branch['tree']),
        'snapshotInfo': dict(branch['snapshotInfo'])
    }
    return Branch(**updated)  # type: ignore


def branchtree_to_branchtreelistitem(
        bt: BranchTree, snapInfo: Dict[CfgId, SnapshotInfo], cfg_id: CfgId) -> BranchTreeListItem:
    def recursor(bt: BranchTree, cfg_id: CfgId, visited: Set[CfgId]) -> BranchTreeListItem:
        children: List[BranchTreeListItem] = []
        snapshot_info = snapInfo[cfg_id]

        for child in (dest for src, dest in bt['edges'] if src == cfg_id and dest not in visited):
            visited.add(child)
            children.append(recursor(bt, child, visited))

        return BranchTreeListItem(cfgId=cfg_id, snapshotInfo=snapshot_info, children=children)

    return recursor(bt, cfg_id, {cfg_id})


def branch_to_list_item(branch: Branch) -> BranchTreeListItem:
    return branchtree_to_branchtreelistitem(
        branch['tree'], branch['snapshotInfo'], branch['rootNode'])


# =================================================================================================


@enum.unique
class SnapTreeColumn(enum.Enum):
    '''
    values are in column order
    '''
    NAME = "Name"
    TYPE = "Category"
    TIME = "Timestamp"


class SnapTreeItem(QTreeWidgetItem):
    def __init__(
            self,
            parent: Union[QTreeWidget, QTreeWidgetItem],
            predecessor: Optional[QTreeWidgetItem] = None):
        '''
        parent: the Q parent widget (either a treeview for a top level item, or a tree item)
        predecessor: the tree item preceding this one
        '''
        # pyright doesn't seem to handle constructor overloading well?
        QTreeWidgetItem.__init__(self, parent, predecessor, type=QTreeWidgetItem.UserType)
        self.update_text()
        ''' From QTreeWidgetItem documentation, for reference:
        By default, items are enabled, selectable, checkable, and can be
        the source of a drag and drop operation. Each item’s flags can be
        changed by calling setFlags() with the appropriate value (see ItemFlags).
        Checkable items can be checked and unchecked with the setCheckState()
        function. The corresponding checkState() function indicates whether the
        item is currently checked.
        '''

    def update_text(self):
        for i, col in enumerate(SnapTreeColumn):
            try:
                txt = self.get_text_for_col(col)
            except Exception as e:  # the show must go on
                txt = ''
            self.setText(i, txt)

    def deep_expand(self):
        parent = self.parent()
        if isinstance(parent, SnapTreeItem):
            parent.deep_expand()
        self.setExpanded(True)

    def get_item_for_cfg(self, cfg_id: CfgId) -> Optional['SnapTreeItem']:
        """
        Checks if this is the item for the given CFG ID, or any of this item's children
        """
        if isinstance(self, SnapTreeBranchItemBase) and self.cfg_id == cfg_id:
            return self

        # TODO are chlidren guaranteed to have an index in the range of childCount()?
        for idx in range(self.childCount()):
            child = cast(SnapTreeItem, self.child(idx))
            if (item := child.get_item_for_cfg(cfg_id)):
                return item

        return None

    def get_text_for_col(self, col: SnapTreeColumn) -> str:
        """
        To be overridden by implementing classes
        Ought to return the text for a given column
        """
        return ""


class SnapTreeBranchItemBase(SnapTreeItem):
    cfg_id: CfgId
    snap_name: Optional[str]


class SnapTreeBranchListItem(SnapTreeBranchItemBase):
    def __init__(
        self,
        parent: QTreeWidgetItem,
    ):
        self.children: Dict[CfgId, SnapTreeBranchListItem] = {}

        SnapTreeItem.__init__(self, parent, None)

    def process_item(self, item: BranchTreeListItem):
        self.item = item  # type: ignore
        self.cfg_id = item['cfgId']
        self.snap_info = item['snapshotInfo']  # type: ignore

        self.snap_name = self.snap_info['name']
        self.timestamp = datetime.fromisoformat(  # type: ignore
            servertime_to_clienttime(self.snap_info['modified']))
        self.update_text()

        children = item['children']
        for child in children:
            if child['cfgId'] in self.children:
                child_item = self.children[child['cfgId']]
            else:
                child_item = SnapTreeBranchListItem(self)
                self.children[child['cfgId']] = child_item
                self.addChild(child_item)
            child_item.process_item(child)

        # trust the server as the absolute truth
        missing_children = set(self.children.keys()) \
                         - set([c['cfgId'] for c in children])
        for c in missing_children:
            child = self.children.pop(c)
            self.removeChild(child)

    def get_text_for_col(self, col: SnapTreeColumn) -> str:
        return {
            SnapTreeColumn.NAME: self.snap_name or f'Snapshot {self.cfg_id[-6:]}',
            SnapTreeColumn.TYPE: self.snap_info['snapshotType'],
            SnapTreeColumn.TIME: self.timestamp.strftime(ITEM_DATE_FMT_OUT),
        }.get(col, '')


class SnapTreeBranchItem(SnapTreeBranchItemBase):
    def __init__(
        self,
        parent: QTreeWidgetItem,
        branch_id: BranchId,
        predecessor: Optional[QTreeWidgetItem] = None,
    ):
        self.children: Dict[CfgId, SnapTreeBranchListItem] = {}
        self.branch_id = branch_id
        self.root_snap: Optional[SnapshotInfo] = None

        self.snap_name = ''
        self.cfg_id = ''
        self.timestamp: Optional[datetime] = None

        SnapTreeItem.__init__(self, parent, predecessor)

    def process_branch_data(self, branch_data: Branch):
        self.branch_data = branch_data  # type: ignore

        self.cfg_id = branch_data['rootNode']
        self.root_snap = branch_data['snapshotInfo'][self.cfg_id]
        self.snap_name = self.root_snap['name']
        self.timestamp = datetime.fromisoformat(
            servertime_to_clienttime(self.root_snap['modified']))
        self.update_text()

        list_item = branch_to_list_item(branch_data)

        for child in list_item['children']:
            cfg_id = child['cfgId']
            if cfg_id in self.children:
                item = self.children[cfg_id]
            else:
                item = SnapTreeBranchListItem(self)
                self.addChild(item)
                self.children[cfg_id] = item
            item.process_item(child)

        # trust the server as the absolute truth
        missing_srcs = set(self.children.keys()) \
                     - set([cfg_id for cfg_id in branch_data['snapshotInfo']])
        for src in missing_srcs:
            item = self.children.pop(src)
            self.removeChild(item)

    def get_text_for_col(self, col: SnapTreeColumn) -> str:
        return {
            SnapTreeColumn.NAME:
                self.snap_name or f'Snapshot {self.cfg_id[-6:]}',
            SnapTreeColumn.TYPE:
                "Branch Root",
            SnapTreeColumn.TIME:
                self.timestamp.strftime('%b %d, %Y @ %H:%M:%S') if self.timestamp else '',
        }.get(col) or ""


class SnapTreeFuncItem(SnapTreeItem):
    def __init__(
        self,
        parent: QTreeWidgetItem,
        func_name: str,
        predecessor: Optional[QTreeWidgetItem] = None,
    ):
        self.func_name = func_name
        self.tracked_branches: Dict[BranchId, SnapTreeBranchItem] = {}
        SnapTreeItem.__init__(self, parent, predecessor)

    def process_branch_data(self, branch_id: BranchId, branch_data: Branch):
        if branch_id in self.tracked_branches:
            item = self.tracked_branches[branch_id]
        else:
            item = SnapTreeBranchItem(self, branch_id)
            self.addChild(item)
            self.tracked_branches[branch_id] = item

        item.process_branch_data(branch_data)

    def get_item_for_cfg(self, cfg_id: CfgId) -> Optional[SnapTreeItem]:
        for bid, bitem in self.tracked_branches.items():
            if (item := bitem.get_item_for_cfg(cfg_id)):
                return item

        return None

    def get_text_for_col(self, col: SnapTreeColumn) -> str:
        return {
            SnapTreeColumn.NAME: self.func_name,
            SnapTreeColumn.TYPE: "Origin Function",
        }.get(col) or ""


class SnapTreeWidget(QTreeWidget):
    '''
    I am the manifestation of a SnapTree into reality
    '''
    def __init__(
            self, parent: QWidget, blaze_instance: 'BlazeInstance'):  #, view_frame: ViewFrame):
        QTreeWidget.__init__(self, parent)
        self.blaze_instance: 'BlazeInstance' = blaze_instance
        # self._view_frame: ViewFrame = view_frame

        headers = [col.value for col in SnapTreeColumn]
        self.setHeaderLabels(headers)
        self.setColumnCount(len(headers))

        self.tracked_funcs: Dict[Address, SnapTreeFuncItem] = {}
        self.focused_icfg: Optional[CfgId] = None

        self.action_handler = UIActionHandler()
        self.action_handler.setupActionHandler(self)
        self.context_menu = Menu()
        self.context_menu_manager = ContextMenuManager(self)

        self.clicked_item: Optional[SnapTreeItem] = None

        # Bind actions to their callbacks
        # yapf: disable
        actions: List[BNAction] = [
            BNAction(
                'Blaze', 'Load Snapshot', MenuOrder.FIRST,
                activate=self.ctx_menu_action_load,
                isValid=lambda ctx: self.clicked_item is not None and
                                    isinstance(self.clicked_item, SnapTreeBranchItemBase)
            ),
            BNAction(
                'Blaze', 'Rename Snapshot', MenuOrder.EARLY,
                activate=self.ctx_menu_action_rename,
                isValid=lambda ctx: self.clicked_item is not None and
                                    isinstance(self.clicked_item, SnapTreeBranchItemBase)
            ),
            # BNAction(
            #     'Blaze', 'Delete Snapshot', MenuOrder.LAST,
            #     activate=self.ctx_menu_action_delete,
            #     isValid=lambda ctx: self.clicked_item is not None
            #                         and 'cfg_id' in self.clicked_item.__dict__
            # ),
        ]
        # yapf: enable

        bind_actions(self.action_handler, actions)
        add_actions(self.context_menu, actions)

        log.debug('%r initialized', self)

    def __del__(self):
        try_debug(log, 'Deleting %r', self)

    def mouseDoubleClickEvent(self, event: QMouseEvent) -> None:
        if event.button() != Qt.LeftButton:
            return super().mousePressEvent(event)

        ev_pos = event.pos()
        if (item := self.itemAt(ev_pos)):
            item = cast(SnapTreeItem, item)
            self.clicked_item = item
            if isinstance(item, SnapTreeBranchItemBase):
                self.load_icfg(item.cfg_id)

    def mousePressEvent(self, event: QMouseEvent) -> None:
        if event.button() != Qt.RightButton:
            return super().mousePressEvent(event)

        ev_pos = event.pos()
        if (item := self.itemAt(ev_pos)):
            item = cast(SnapTreeItem, item)
            self.clicked_item = item
            self.context_menu_manager.show(self.context_menu, self.action_handler)

    def ctx_menu_action_load(self, context: UIActionContext) -> None:
        if not self.clicked_item:
            return

        if isinstance(self.clicked_item, SnapTreeBranchItemBase):
            self.load_icfg(self.clicked_item.cfg_id)

    def ctx_menu_action_rename(self, context: UIActionContext) -> None:
        if not self.clicked_item:
            return

        if isinstance(self.clicked_item, SnapTreeBranchItemBase):
            self.rename_snapshot(self.clicked_item)

    def ctx_menu_action_delete(self, context: UIActionContext) -> None:
        if not self.clicked_item:
            return

        if isinstance(self.clicked_item, SnapTreeBranchItemBase):
            self.delete_snapshot(self.clicked_item.cfg_id)

    def update_branches_of_binary(self, branches: List[Tuple[BranchId, ServerBranch]]) -> None:
        for bid, _data in branches:
            data = branch_from_server(_data)
            func_addr = data['originFuncAddr']

            if func_addr in self.tracked_funcs:
                item = self.tracked_funcs.get(func_addr)
            else:
                item = SnapTreeFuncItem(self, data['originFuncName'])  # type: ignore
                self.tracked_funcs[func_addr] = item
                self.addTopLevelItem(item)
                self.expandItem(item)

            if item:
                item.process_branch_data(bid, data)
            else:
                log.error(r'No matching item for function at 0x%x', func_addr)

        self.clean_stale_branches([bid for bid, _ in branches])
        if self.focused_icfg:
            self.focus_icfg(self.focused_icfg)

    def clean_stale_branches(self, server_bids: List[BranchId]):
        # TODO delete all BranchItems that were not received from the server
        tracked_bids = []
        for f, fitem in self.tracked_funcs.items():
            for bid in fitem.tracked_branches:
                if bid not in server_bids:
                    # TODO delete fitem.tracked_branches[bid]
                    pass

    def focus_icfg(self, cfg_id: CfgId) -> None:
        self.focused_icfg = cfg_id
        if (item := self.get_item_for_cfg(cfg_id)):
            for _item in self.selectedItems():
                _item.setSelected(False)
            item.deep_expand()
            self.setCurrentItem(item)
            item.setSelected(True)

    def load_icfg(self, cfg_id: CfgId) -> None:
        log.info(f'Loading snapshot for icfg {cfg_id}')
        snapshot_msg = SnapshotBinjaToServer(tag='LoadSnapshot', cfgId=cfg_id)

        for instance in self.blaze_instance.blaze.instances_by_key(self.blaze_instance.bv_key):
            instance.icfg_dock_widget.icfg_widget.recenter_node_id = None

        self.blaze_instance.send(BinjaToServer(tag='BSSnapshot', snapshotMsg=snapshot_msg))

    def get_item_for_cfg(self, cfg_id: CfgId) -> Optional[SnapTreeItem]:
        for f, fitem in self.tracked_funcs.items():
            if (item := fitem.get_item_for_cfg(cfg_id)):
                return item
        return None

    def rename_snapshot(self, item: SnapTreeBranchItemBase) -> None:
        text_in = TextLineField("Rename snapshot to:")
        confirm: bool = get_form_input([text_in], f'Renaming {item.snap_name or item.cfg_id}')

        if not confirm:
            return

        snap_msg = SnapshotBinjaToServer(
            tag='RenameSnapshot', cfgId=item.cfg_id, name=cast(str, text_in.result))
        self.blaze_instance.send(BinjaToServer(tag='BSSnapshot', snapshotMsg=snap_msg))

    def delete_snapshot(self, cfg_id: CfgId) -> None:
        log.error("Fool, there is no getting rid of a snapshot!")

    def notifyOffsetChanged(self, view_frame: ViewFrame, offset: int) -> None:
        pass


class SnapTreeDockWidget(QWidget, DockContextHandler):
    '''
    I talk to the greater Binja context on behalf of the SnapTreeWidget
    '''
    def __init__(
            self, name: str, view_frame: ViewFrame, parent: QWidget,
            blaze_instance: 'BlazeInstance'):
        QWidget.__init__(self, parent)
        DockContextHandler.__init__(self, self, name)

        self._view_frame: ViewFrame = view_frame
        self.blaze_instance: 'BlazeInstance' = blaze_instance
        self.snaptree_widget = SnapTreeWidget(self, blaze_instance)  #, view_frame)

        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addWidget(self.snaptree_widget)
        self.setLayout(layout)

        log.debug('%r initialized', self)

    def __del__(self):
        try_debug(log, 'Deleting %r', self)

        # self.snaptree_widget._debug_()

    def notifyOffsetChanged(self, offset: int) -> None:
        self.snaptree_widget.notifyOffsetChanged(self._view_frame, offset)
