import enum
import logging as _logging
import os
from datetime import datetime
from typing import TYPE_CHECKING, Dict, List, Optional, Set, Tuple, Union, cast

import binaryninjaui
from binaryninjaui import (
    ContextMenuManager,
    DockContextHandler,
    Menu,
    UIActionHandler,
    ViewFrame,
)

if getattr(binaryninjaui, 'qt_major_version', None) == 6:
    from PySide6.QtCore import Qt  # type: ignore
    from PySide6.QtWidgets import (  # type: ignore
        QTreeWidget, QTreeWidgetItem, QTreeWidgetItemIterator, QVBoxLayout, QWidget)  # type: ignore
else:
    from PySide2.QtCore import Qt  # type: ignore
    from PySide2.QtWidgets import (  # type: ignore
        QTreeWidget, QTreeWidgetItem, QTreeWidgetItemIterator, QVBoxLayout, QWidget)  # type: ignore

from .types import (
    BinjaToServer,
    Branch,
    BranchId,
    BranchTree,
    BranchTreeListItem,
    CfgId,
    HostBinaryPath,
    ServerBranch,
    ServerBranchesOfClient,
    ServerBranchTree,
    SnapshotBinjaToServer,
    SnapshotInfo,
    SnapshotServerToBinja,
)

if TYPE_CHECKING:
    from .client_plugin import BlazeInstance

log = _logging.getLogger(__name__)

# =================================================================================================


def branch_tree_from_server(branch_tree: ServerBranchTree) -> BranchTree:
    edges = [edge[1] for edge in branch_tree['edges']]
    return BranchTree(edges=edges)


def branch_from_server(branch: ServerBranch) -> Branch:
    updated = {
        **branch, 'tree': branch_tree_from_server(branch['tree']),
        'snapshotInfo': dict(branch['snapshotInfo'])
    }
    return Branch(**updated)


def branchtree_to_branchtreelistitem(
        bt: BranchTree, snapInfo: Dict[CfgId, SnapshotInfo], cfg_id: CfgId) -> BranchTreeListItem:
    def recursor(bt: BranchTree, cfg_id: CfgId, visited: Set[CfgId]) -> BranchTreeListItem:
        children = []
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
        QTreeWidgetItem.__init__(
            self,
            parent,  # type: ignore
            predecessor,  # type: ignore
            type=QTreeWidgetItem.UserType)

        for i, col in enumerate(SnapTreeColumn):
            self.setText(i, self.get_text_for_col(col))
        ''' From QTreeWidgetItem documentation, for reference:
        By default, items are enabled, selectable, checkable, and can be
        the source of a drag and drop operation. Each item’s flags can be
        changed by calling setFlags() with the appropriate value (see ItemFlags).
        Checkable items can be checked and unchecked with the setCheckState()
        function. The corresponding checkState() function indicates whether the
        item is currently checked.
        '''

    def get_text_for_col(self, col: SnapTreeColumn) -> str:
        """
        To be overridden by implementing classes
        Ought to return the text for a given column
        """
        return ""

    '''
    def get_child(self, identifier):
        for idx in range(self.childCount()):
            child = self.child(idx)
            # TODO this check better
            if child.text(0) == identifier:
                return child
    '''


class SnapTreeBranchListItem(SnapTreeItem):
    def __init__(
        self,
        parent: QTreeWidgetItem,
        branch_id: BranchId,
        item: BranchTreeListItem,
    ):
        self.item = item
        self.branch_id = branch_id
        self.snap_info = item.get('snapshotInfo')
        self.timestamp = datetime.fromisoformat(
            self.snap_info.get('created')[:len('YYYY-DD-SSTHH:MM:SS')]  # TODO or modified?
        )
        SnapTreeItem.__init__(self, parent, None)

        self.process_children(item.get('children'))

    def process_children(self, children: List[BranchTreeListItem]):
        for child in children:
            child = SnapTreeBranchListItem(self, self.branch_id, child)
            self.addChild(child)

    def get_text_for_col(self, col: SnapTreeColumn) -> str:
        return {
            SnapTreeColumn.NAME: self.snap_info.get('name') or "<<Snapshot>>",
            SnapTreeColumn.TYPE: self.snap_info.get('snapshotType'),
            SnapTreeColumn.TIME: self.timestamp.strftime('%b %d, %Y @ %H:%M:%S'),
        }.get(col) or ""


class SnapTreeBranchItem(SnapTreeItem):
    def __init__(
        self,
        parent: QTreeWidgetItem,
        branch_id: BranchId,
        branch_data: ServerBranch,
        predecessor: Optional[QTreeWidgetItem] = None,
    ):
        self.branch_id = branch_id
        self.branch_data = branch_data
        self.children = {}
        SnapTreeItem.__init__(self, parent, predecessor)

        self.process_branch_data(branch_data)

    def process_branch_data(self, branch_data: ServerBranch):
        self.branch_data = branch_data

        self.branch = branch_from_server(branch_data)
        list_item = branch_to_list_item(self.branch)
        child = SnapTreeBranchListItem(self, self.branch_id, list_item)
        self.addChild(child)

    def get_text_for_col(self, col: SnapTreeColumn) -> str:
        return {
            SnapTreeColumn.NAME:
                self.branch_data.get('branchName') or self.branch_data.get('originFuncName'),
            SnapTreeColumn.TYPE:
                "Branch Tree",
        }.get(col) or ""


class SnapTreeBinaryItem(SnapTreeItem):
    def __init__(
            self, parent: QTreeWidget, binary_path: str, branches: List[Tuple[BranchId,
                                                                              ServerBranch]]):
        self.binary_path: str = binary_path
        self.branches: Dict[BranchId, SnapTreeBranchItem] = {}

        SnapTreeItem.__init__(self, parent)

        self.add_branches(branches)

    def add_branches(self, branches: List[Tuple[BranchId, ServerBranch]]):
        self.addChildren([SnapTreeBranchItem(self, bid, bdata) for bid, bdata in branches])

    def get_text_for_col(self, col: SnapTreeColumn) -> str:
        return {
            SnapTreeColumn.NAME: self.bin_path_to_label(self.binary_path),
            SnapTreeColumn.TYPE: "Binary Path"
        }.get(col) or ""

    @classmethod
    def bin_path_to_label(cls, bpath) -> str:
        ''' TODO
        A unified way to get a searchable binary path for getting this Item
        through QTreeWidget.findItems()
        '''
        return os.path.basename(bpath)


class SnapTreeWidget(QTreeWidget):
    '''
    I am the manifestation of a SnapTree into reality
    '''
    def __init__(
            self, parent: QWidget, blaze_instance: 'BlazeInstance'):  #, view_frame: ViewFrame):
        QTreeWidget.__init__(self, parent)
        self.blaze_instance: 'BlazeInstance' = blaze_instance
        # self._view_frame: ViewFrame = view_frame

        self.action_handler = UIActionHandler()
        self.action_handler.setupActionHandler(self)
        self.context_menu = Menu()
        self.context_menu_manager = ContextMenuManager(self)
        self.tracked_binaries: List[HostBinaryPath] = []

        headers = [col.value for col in SnapTreeColumn]
        self.setHeaderLabels(headers)
        self.setColumnCount(len(headers))
        self.itemDoubleClicked.connect(self._dispatch_double_click)

        log.debug('%r initialized', self)

    def __del__(self):
        log.debug(f'Deleting {self!r}')

    def _dispatch_double_click(self, item: SnapTreeItem, column: int) -> None:
        if isinstance(item, SnapTreeBranchListItem):
            snap = cast(SnapTreeBranchListItem, item)
            cfg_id = snap.item['cfgId']
            self.load_icfg(cfg_id)

    def update_branches_of_client(self, data: ServerBranchesOfClient) -> None:
        self.clear()
        self.addTopLevelItems(
            [SnapTreeBinaryItem(self, bpath, branches) for bpath, branches in data])

        # TODO placeholder for logic for snaptree clarity
        # self.on_update(data['currentCfg'])

    def update_branches_of_binary(
            self, bin_path: HostBinaryPath, branches: List[Tuple[BranchId, ServerBranch]]):
        if binary_item := self.find_binary_item(bin_path):
            # this is the only way I can find that removes a TLI from the tree?
            self.takeTopLevelItem(self.indexOfTopLevelItem(binary_item))

        self.addTopLevelItem(SnapTreeBinaryItem(self, bin_path, branches))

        # TODO placeholder for logic for snaptree clarity
        # self.on_update(data['currentCfg'])

    def on_update(self, current_cfg: str) -> None:
        # TODO
        # item = get current snap item
        # collapse all items
        # for item in tree:
        #     item.setExpanded( item is in path for current_cfg )
        # self.scrollToItem(item)
        pass

    def find_binary_item(self, bin_path: HostBinaryPath) -> Optional[SnapTreeBinaryItem]:
        if bin_path not in self.tracked_binaries:
            return None

        items = self.findItems(
            SnapTreeBinaryItem.bin_path_to_label(bin_path), Qt.MatchFlag.MatchExactly)

        return cast(SnapTreeBinaryItem, items[0]) if items else None

    def load_icfg(self, cfg_id: CfgId) -> None:
        log.info(f'Loading snapshot for icfg {cfg_id}')
        snapshot_msg = SnapshotBinjaToServer(tag='LoadSnapshot', cfgId=cfg_id)

        self.blaze_instance.blaze.icfg_dock_widget.icfg_widget.recenter_node_id = None
        self.blaze_instance.send(BinjaToServer(tag='BSSnapshot', snapshotMsg=snapshot_msg))

    def notifyInstanceChanged(self, blaze_instance: 'BlazeInstance', view_frame: ViewFrame):
        self.blaze_instance = blaze_instance
        self._view_frame = view_frame

    def notifyOffsetChanged(self, view_frame: ViewFrame, offset: int) -> None:
        pass

    def _debug_(self):
        it = QTreeWidgetItemIterator(self)
        while it.value():
            item = it.value()
            item.setExpanded(True)
            log.debug(f"{item.text(0)} parent: {item.parent().text(0) if item.parent() else '---'}")
            log.debug(f"{item.text(0)} expanded: {item.isExpanded()}")
            log.debug(f"{item.text(0)} disabled: {item.isDisabled()}")
            it.__next__()


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
        self.blaze_instance: Optional['BlazeInstance'] = blaze_instance
        self.snaptree_widget = SnapTreeWidget(self, blaze_instance)  #, view_frame)

        layout = QVBoxLayout()  # type: ignore
        layout.setContentsMargins(0, 0, 0, 0)  # type: ignore
        layout.setSpacing(0)
        layout.addWidget(self.snaptree_widget)
        self.setLayout(layout)

        log.debug('%r initialized', self)

    def __del__(self):
        log.debug(f'Deleting {self!r}')

    def handle_server_msg(self, snap_msg: SnapshotServerToBinja):
        '''
        this is where I delegate snapshot server messages
        '''
        if snap_msg.get('tag') == 'BranchesOfClient':
            self.snaptree_widget.update_branches_of_client(
                cast(ServerBranchesOfClient, snap_msg.get('branchesOfClient')))

        if snap_msg.get('tag') == 'BranchesOfBinary':
            self.snaptree_widget.update_branches_of_binary(
                cast(HostBinaryPath, snap_msg.get('hostBinaryPath')),
                cast(list, snap_msg.get('branches')))

        # self.snaptree_widget._debug_()

    def notifyViewChanged(self, view_frame: ViewFrame) -> None:
        self._view_frame = view_frame
        if view_frame is None:
            self.blaze_instance = None
        else:
            view = view_frame.getCurrentViewInterface()
            self.blaze_instance = self.blaze_instance.blaze.ensure_instance(view.getData())
            self.snaptree_widget.notifyInstanceChanged(self.blaze_instance, view_frame)

    def notifyOffsetChanged(self, offset: int) -> None:
        self.snaptree_widget.notifyOffsetChanged(self._view_frame, offset)
