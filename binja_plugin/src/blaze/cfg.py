import logging as _logging
from copy import deepcopy
from typing import TYPE_CHECKING, Dict, List, Optional, Tuple, cast

from binaryninja import BinaryView
from binaryninja.enums import BranchType, EdgePenStyle, HighlightStandardColor, ThemeColor
from binaryninja.flowgraph import EdgeStyle, FlowGraph, FlowGraphEdge, FlowGraphNode
from binaryninjaui import (
    ContextMenuManager,
    DockContextHandler,
    FlowGraphWidget,
    Menu,
    UIActionContext,
    UIActionHandler,
    ViewFrame,
)
from PySide2.QtCore import QObject, Qt
from PySide2.QtGui import QContextMenuEvent, QMouseEvent
from PySide2.QtWidgets import QVBoxLayout, QWidget

from .types import (
    UUID,
    BasicBlockNode,
    BinjaToServer,
    CallNode,
    CfEdge,
    Cfg,
    CfgId,
    CfNode,
    EnterFuncNode,
    LeaveFuncNode,
    MenuOrder,
    ServerCfg,
)
from .util import BNAction, add_actions, bind_actions, fix_flowgraph_edge

if TYPE_CHECKING:
    from .client_plugin import BlazeInstance

log = _logging.getLogger(__name__)


def cfg_from_server(cfg: ServerCfg) -> Cfg:
    nodes = {k['contents']['uuid']: v for k, v in cfg['nodes']}
    return Cfg(nodes=nodes, edges=cfg['edges'], root=cfg['root']['contents']['uuid'])


def cfg_to_server(cfg: Cfg) -> ServerCfg:
    nodes = [(cfg['nodes'][k], v) for k, v in cfg['nodes'].items()]
    return ServerCfg(nodes=nodes, edges=cfg['edges'], root=cfg['nodes'][cfg['root']])


def get_edge_type(edge: CfEdge, cfg: Cfg) -> Tuple[BranchType, Optional[EdgeStyle]]:
    node_from = cfg['nodes'][edge['src']['contents']['uuid']]

    if node_from['tag'] == 'Call':
        return (BranchType.UserDefinedBranch,
                EdgeStyle(
                    style=EdgePenStyle.DotLine, theme_color=ThemeColor.UnconditionalBranchColor))

    return {
        'TrueBranch': (BranchType.TrueBranch, None),
        'FalseBranch': (BranchType.FalseBranch, None),
        'UnconditionalBranch': (BranchType.UnconditionalBranch, None),
    }[edge['branchType']]


def format_block_header(node: CfNode) -> str:
    node_id = node['contents']['uuid']
    node_tag = node['tag']

    if node_tag == 'BasicBlock':
        node_contents = cast(BasicBlockNode, node['contents'])
        return f'{node_contents["start"]:#x} (id {node_id}) BasicBlockNode'

    if node_tag == 'Call':
        node_contents = cast(CallNode, node['contents'])
        return f'{node_contents["start"]:#x} (id {node_id}) CallNode'

    if node_tag == 'EnterFunc':
        node_contents = cast(EnterFuncNode, node['contents'])
        prevFun = node_contents['prevCtx']['func']['name']
        nextFun = node_contents['nextCtx']['func']['name']
        return f'(id {node_id}) EnterFuncNode {prevFun} -> {nextFun}'

    if node_tag == 'LeaveFunc':
        node_contents = cast(LeaveFuncNode, node['contents'])
        prevFun = node_contents['prevCtx']['func']['name']
        nextFun = node_contents['nextCtx']['func']['name']
        return f'(id {node_id}) LeaveFuncNode {nextFun} <- {prevFun}'

    assert False, f'Inexaustive match on CFNode? tag={node["tag"]}'


class ICFGFlowGraph(FlowGraph):
    def __init__(self, _bv: BinaryView, cfg: Cfg, cfg_id: CfgId):
        super().__init__()
        self.pil_icfg: Cfg = cfg
        self.pil_icfg_id: CfgId = cfg_id
        self.node_mapping: Dict[FlowGraphNode, CfNode] = {}

        nodes: Dict[UUID, FlowGraphNode] = {}

        for (node_id, node) in cfg['nodes'].items():
            fg_node = FlowGraphNode(self)
            self.node_mapping[fg_node] = node

            fg_node.lines = [format_block_header(node)]
            if (nodeData := node.get('contents', {}).get('nodeData', None)):
                fg_node.lines += nodeData

            if node['tag'] == 'Call':
                fg_node.highlight = HighlightStandardColor.YellowHighlightColor
            elif node['tag'] == 'EnterFunc':
                fg_node.highlight = HighlightStandardColor.GreenHighlightColor
            elif node['tag'] == 'LeaveFunc':
                fg_node.highlight = HighlightStandardColor.BlueHighlightColor

            nodes[node_id] = fg_node
            self.append(fg_node)

        for edge in cfg['edges']:
            branch_type, edge_style = get_edge_type(edge, cfg)
            nodes[edge['src']['contents']['uuid']].add_outgoing_edge(
                branch_type, nodes[edge['dst']['contents']['uuid']], edge_style)

    @property
    def nodes(self):
        return self.pil_icfg['nodes']

    def get_edge(self, source_id: str = None, dest_id: str = None) -> Optional[CfEdge]:
        for edge in self.pil_icfg['edges']:
            if (source_id is None or edge['src']['contents']['uuid'] == source_id) and \
               (dest_id is None or edge['dst']['contents']['uuid'] == dest_id):
                return edge

        return None


class ICFGWidget(FlowGraphWidget, QObject):
    def __init__(self, parent: QWidget, view_frame: ViewFrame, blaze_instance: 'BlazeInstance'):
        FlowGraphWidget.__init__(self, parent, blaze_instance.bv, None)
        self._view_frame: ViewFrame = view_frame
        self.blaze_instance: 'BlazeInstance' = blaze_instance

        self.action_handler = UIActionHandler()
        self.action_handler.setupActionHandler(self)
        self.context_menu = Menu()
        self.context_menu_manager = ContextMenuManager(self)

        self.last_node: Optional[FlowGraphNode] = None
        self.last_edge: Optional[FlowGraphEdge] = None

        # Bind actions to their callbacks

        actions: List[BNAction] = [
            BNAction('Blaze', 'Prune', MenuOrder.FIRST, self.context_menu_action_prune),
            BNAction('Blaze', 'Expand Call Node', MenuOrder.EARLY,
                     self.context_menu_action_expand_call),
        ]

        bind_actions(self.action_handler, actions)
        add_actions(self.context_menu, actions)

    def set_icfg(self, cfg_id: CfgId, cfg: Cfg):
        self.blaze_instance.graph = ICFGFlowGraph(self.blaze_instance.bv, cfg, cfg_id)
        self.setGraph(self.blaze_instance.graph)

    def prune(self, from_node: CfNode, to_node: CfNode):
        '''
        Send a request to the backend that the edge between `from_node` and
        `to_node` be pruned
        '''

        from_node = deepcopy(from_node)
        to_node = deepcopy(to_node)
        from_node['contents']['nodeData'] = []
        to_node['contents']['nodeData'] = []

        self.blaze_instance.send(
            BinjaToServer(
                tag='BSCfgRemoveBranch',
                cfgId=self.blaze_instance.graph.pil_icfg_id,
                edge=(from_node, to_node)))

    def expand_call(self, node: CallNode):
        '''
        Send a request to the backend that the `CallNode` `node` be expanded
        '''

        call_node = node.copy()
        call_node['nodeData'] = []
        # log.info(json.dumps(call_node, indent=2))
        self.blaze_instance.send(
            BinjaToServer(
                tag='BSCfgExpandCall',
                cfgId=self.blaze_instance.graph.pil_icfg_id,
                callNode=call_node))

    def context_menu_action_prune(self, context: UIActionContext):
        '''
        Context menu action to call `self.prune`. Assumes `self.last_edge` has already
        been set by `self.mousePressEvent`
        '''

        if self.last_edge is None:
            log.error('Did not right-click on an edge')
            return

        source_node = self.blaze_instance.graph.node_mapping.get(self.last_edge.source)
        dest_node = self.blaze_instance.graph.node_mapping.get(self.last_edge.target)
        if source_node is None or dest_node is None:
            raise RuntimeError('Missing node in node_mapping!')

        edge = self.blaze_instance.graph.get_edge(source_node['contents']['uuid'],
                                                  dest_node['contents']['uuid'])
        if not edge:
            raise RuntimeError('Missing edge!')

        if edge['branchType'] not in ('TrueBranch', 'FalseBranch'):
            raise ValueError('Not a conditional branch')

        from_node = edge['src']
        to_node = edge['dst']

        self.prune(from_node, to_node)

    def context_menu_action_expand_call(self, context: UIActionContext):
        '''
        Context menu action to call `self.expand_call`. Assumes `self.last_node` has already
        been set by `self.mousePressEvent`
        '''

        if not self.last_node:
            log.error(f'Did not right-click on a CFG node')
            return

        node = self.blaze_instance.graph.node_mapping.get(self.last_node)
        if not node or node['tag'] != 'Call':
            log.error(f'Did not right-click on a Call node')
            return

        call_node = cast(CallNode, node['contents'])
        self.expand_call(call_node)

    def mouseDoubleClickEvent(self, event: QMouseEvent) -> None:
        '''
        Expand the call node under mouse, if any
        '''

        if event.button() != Qt.LeftButton or self.blaze_instance.graph is None:
            return super().mousePressEvent(event)

        if (fg_node := self.getNodeForMouseEvent(event)):
            node = self.blaze_instance.graph.node_mapping.get(fg_node)

            if not node:
                log.error(f'Couldn\'t find node_mapping[{fg_node}]')
                return

            if node['tag'] != 'Call':
                log.warning('Did not double-click on a node')
                return

            call_node = cast(CallNode, node['contents'])
            self.expand_call(call_node)

    def contextMenuEvent(self, event: QContextMenuEvent) -> None:
        '''
        Do nothing, to override the parent (`FlowGraphWidget`) behavior
        '''
        return

    def mousePressEvent(self, event: QMouseEvent):
        '''
        If the right mouse button was clicked, remember the node or edge (if any)
        under the mouse, and show the context menu
        '''

        if event.button() != Qt.MouseButton.RightButton:
            return super().mousePressEvent(event)

        self.last_node = self.getNodeForMouseEvent(event)
        if (fg_edge := self.getEdgeForMouseEvent(event)):
            fg_edge, swapped = fg_edge
            self.last_edge = fix_flowgraph_edge(fg_edge, swapped)
        else:
            self.last_edge = None

        self.context_menu_manager.show(self.context_menu, self.action_handler)

    def notifyInstanceChanged(self, blaze_instance: 'BlazeInstance', view_frame: ViewFrame):
        self.blaze_instance = blaze_instance
        self._view_frame = view_frame

    def notifyOffsetChanged(self, view_frame: ViewFrame, offset: int) -> None:
        pass


class ICFGDockWidget(QWidget, DockContextHandler):
    def __init__(self, name: str, view_frame: ViewFrame, parent: QWidget,
                 blaze_instance: 'BlazeInstance'):
        QWidget.__init__(self, parent)
        DockContextHandler.__init__(self, self, name)

        self._view_frame: ViewFrame = view_frame
        self.blaze_instance: Optional['BlazeInstance'] = blaze_instance
        self.icfg_widget: ICFGWidget = ICFGWidget(self, view_frame, self.blaze_instance)

        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addWidget(self.icfg_widget)
        self.setLayout(layout)

    def notifyViewChanged(self, view_frame: ViewFrame) -> None:
        self._view_frame = view_frame
        if view_frame is None:
            self.blaze_instance = None
        else:
            view = view_frame.getCurrentViewInterface()
            self.blaze_instance = self.blaze_instance.blaze.ensure_instance(view.getData())
            self.icfg_widget.notifyInstanceChanged(self.blaze_instance, view_frame)

    def notifyOffsetChanged(self, offset: int) -> None:
        self.icfg_widget.notifyOffsetChanged(self._view_frame, offset)
