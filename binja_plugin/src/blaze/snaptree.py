import logging as _logging
from typing import TYPE_CHECKING, List, Optional, Set, Tuple, Union, cast, Dict

from binaryninjaui import (
    ContextMenuManager,
    DockContextHandler,
    Menu,
    UIActionContext,
    UIActionHandler,
    ViewFrame,
)

import binaryninjaui
if getattr(binaryninjaui, 'qt_major_version', None) == 6:
    from PySide6.QtGui import QMouseEvent
    from PySide6.QtWidgets import QTreeWidget, QTreeWidgetItem, QTreeWidgetItemIterator, QVBoxLayout, QWidget
else:
    from PySide2.QtGui import QMouseEvent
    from PySide2.QtWidgets import QTreeWidget, QTreeWidgetItem, QTreeWidgetItemIterator, QVBoxLayout, QWidget

from .types import (
    BINARYNINJAUI_CUSTOM_EVENT,
    UUID,
    BinjaToServer,
    Branch,
    BranchId,
    BranchTree,
    BranchTreeListItem,
    CfgId,
    HostBinaryPath,
    MenuOrder,
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


class SnapTree():
    '''
    I handle the logic for comprehending a snapshot tree
    '''
    def __init__(self):
        pass


def branch_tree_from_server(branch_tree: ServerBranchTree) -> BranchTree:
    edges = [edge[1] for edge in branch_tree['edges']]
    return BranchTree(edges=edges)


def branch_from_server(branch: ServerBranch) -> Branch:
    updated = {**branch, 'tree': branch_tree_from_server(branch['tree']), 'snapshotInfo': dict(branch['snapshotInfo'])}
    return Branch(**updated)


def branchtree_to_branchtreelistitem(bt: BranchTree, snapInfo: Dict[CfgId, SnapshotInfo], cfg_id: CfgId) -> BranchTreeListItem:
    def recursor(bt: BranchTree, cfg_id: CfgId, visited: Set[CfgId]) -> BranchTreeListItem:
        children = []
        snapshot_info = snapInfo[cfg_id]

        for child in (dest for src, dest in bt['edges'] if src == cfg_id and dest not in visited):
            visited.add(child)
            children.append(recursor(bt, child, visited))

        return BranchTreeListItem(cfgId=cfg_id, snapshotInfo=snapshot_info, children=children)

    return recursor(bt, cfg_id, {cfg_id})


def branch_to_list_item(branch: Branch) -> BranchTreeListItem:
    return branchtree_to_branchtreelistitem(branch['tree'], branch['snapshotInfo'], branch['rootNode'])


class SnapTreeItem(QTreeWidgetItem):
    def __init__(
            self,
            parent: Union[QTreeWidget, QTreeWidgetItem],
            predecessor: Optional[QTreeWidgetItem] = None,
            text: Tuple[str] = tuple()
    ):
        '''
        parent: the Q parent widget (either a treeview for a top level item, or a tree item)
        predecessor: the tree item preceding this one
        '''
        # pyright doesn't seem to handle constructor overloading well?
        QTreeWidgetItem.__init__(
            self,
            parent,                          # type: ignore
            predecessor,                      # type: ignore
            type=QTreeWidgetItem.UserType
        )
        for i, t in enumerate(text):
            self.setText(i, t)

        '''
        By default, items are enabled, selectable, checkable, and can be
        the source of a drag and drop operation. Each item’s flags can be
        changed by calling setFlags() with the appropriate value (see ItemFlags).
        Checkable items can be checked and unchecked with the setCheckState()
        function. The corresponding checkState() function indicates whether the
        item is currently checked.
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

        date = item['snapshotInfo']['created']
        if item['snapshotInfo']['snapshotType'] == 'Autosave':
            text = (f"Autosave: {date}:")
        else:
            name = item['snapshotInfo']['name'] or (f"{date}")
            text = (f"Snapshot: {name}")
        SnapTreeItem.__init__(self, parent, None, (text,))

        for child in item['children']:
            self.addChild(SnapTreeBranchListItem(self, self.branch_id, child))


class SnapTreeBranchItem(SnapTreeItem):
    def __init__(
            self,
            parent: QTreeWidgetItem,
            branch_id: BranchId,
            branch_data: ServerBranch,
            predecessor: Optional[QTreeWidgetItem] = None,
    ):
        self.branch_id = branch_id
        self.branch = branch_from_server(branch_data)
        self.branch_tree_list_item = branch_to_list_item(self.branch)
        origin_func_name = self.branch['originFuncName']

        text = (f"Branch {origin_func_name}:",) # {str(branch_data)}",)
        SnapTreeItem.__init__(self, parent, predecessor, text)

        self.addChild(SnapTreeBranchListItem(self, branch_id, self.branch_tree_list_item))


class SnapTreeBinaryItem(SnapTreeItem):
    def __init__(
            self,
            parent: QTreeWidget,
            binary_path: str,
            branches: List[Tuple[BranchId, ServerBranch]]
    ):
        SnapTreeItem.__init__(self, parent, text=(binary_path,))
        self.process_branches(branches)

    def process_branches(self, branches: List[Tuple[BranchId, ServerBranch]]):
        last_branch = None
        for bid, bdata in branches:
            last_branch = SnapTreeBranchItem(self, bid, bdata)#, last_branch)
            self.addChild(last_branch)


class SnapTreeWidget(QTreeWidget):
    '''
    I am the manifestation of a SnapTree into reality
    '''
    def __init__(self, blaze_instance: 'BlazeInstance', parent: QWidget): #, view_frame: ViewFrame, blaze_instance: 'BlazeInstance'):
        QTreeWidget.__init__(self, parent)
        # self._view_frame: ViewFrame = view_frame
        # self.blaze_instance: 'BlazeInstance' = blaze_instance

        self.action_handler = UIActionHandler()
        self.action_handler.setupActionHandler(self)
        self.context_menu = Menu()
        self.context_menu_manager = ContextMenuManager(self)
        self.blaze_instance = blaze_instance

        # TODO this is temp data
        headers = ["test"]
        self.setHeaderLabels(headers)
        self.setColumnCount(len(headers))
        self.itemDoubleClicked.connect(lambda item, c: self.load_icfg(item))

    def insert_branches_of_client(self, data: ServerBranchesOfClient):
        self.clear()
        self.addTopLevelItems(
            [SnapTreeBinaryItem(self, bpath, branches) for bpath, branches in data]
        )
        self._debug_()

    def _debug_(self):
        it = QTreeWidgetItemIterator(self)
        while it.value():
            item = it.value()
            item.setExpanded(True)
            log.info(f"{item.text(0)}: {item.parent().text(0) if item.parent() else '---'}")
            log.info(f"{item.text(0)}: {item.isExpanded()}")
            log.info(f"{item.text(0)}: {item.isDisabled()}")
            it.__next__()

    def load_icfg(self, x):
        # TODO: check for type to make sure it's a SnapTreeBranchListItem
        snap = cast(SnapTreeBranchListItem, x)
        cfg_id = snap.item['cfgId']
        log.info(f'Loading icfg {cfg_id}')
        snapshot_msg = SnapshotBinjaToServer(tag='LoadSnapshot', cfgId=snap.item['cfgId'])

        self.blaze_instance.blaze.icfg_dock_widget.icfg_widget.recenter_node_id = None
        self.blaze_instance.send(BinjaToServer(tag='BSSnapshot', snapshotMsg=snapshot_msg))

    def notifyInstanceChanged(self, blaze_instance: 'BlazeInstance', view_frame: ViewFrame):
        self.blaze_instance = blaze_instance
        self._view_frame = view_frame

    def notifyOffsetChanged(self, view_frame: ViewFrame, offset: int) -> None:
        pass



class SnapTreeDockWidget(QWidget, DockContextHandler):
    '''
    I talk to the greater Binja context on behalf of the SnapTreeWidget
    '''
    def __init__(
            self, name: str,
            view_frame: ViewFrame,
            parent: QWidget,
            blaze_instance: 'BlazeInstance'
    ):
        QWidget.__init__(self, parent)
        DockContextHandler.__init__(self, self, name)

        self._view_frame: ViewFrame = view_frame
        self.blaze_instance: Optional['BlazeInstance'] = blaze_instance
        self.snaptree_widget = SnapTreeWidget(blaze_instance, self) #, view_frame, self.blaze_instance)

        layout = QVBoxLayout()  # type: ignore
        layout.setContentsMargins(0, 0, 0, 0)  # type: ignore
        layout.setSpacing(0)
        layout.addWidget(self.snaptree_widget)
        self.setLayout(layout)

    def handle_server_msg(self, snap_msg: SnapshotServerToBinja):
        '''
        this is where I delegate snapshot server messages
        '''
        log.info(snap_msg)

        if snap_msg['tag'] == 'BranchesOfClient':
            self.snaptree_widget.insert_branches_of_client(
                cast(ServerBranchesOfClient, snap_msg.get('branchesOfClient'))
            )

    def notifyViewChanged(self, view_frame: ViewFrame) -> None:
        self._view_frame = view_frame
        if view_frame is None:
            self.blaze_instance = None
        else:
            view = view_frame.getCurrentViewInterface()
            self.blaze_instance = self.blaze_instance.blaze.ensure_instance(view.getData())
            self.snaptree_widget.notifyInstanceChanged(self.blaze_instance, view_frame)

    def notifyOffsetChanged(self, offset:int) -> None:
        self.snaptree_widget.notifyOffsetChanged(self._view_frame, offset)
