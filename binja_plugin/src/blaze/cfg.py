import logging as _logging
from copy import deepcopy
from typing import TYPE_CHECKING, Dict, List, Optional, Tuple, Union, cast

from binaryninja import BinaryView
from binaryninja.enums import BranchType, EdgePenStyle, HighlightStandardColor, ThemeColor
from binaryninja.flowgraph import EdgeStyle, FlowGraph, FlowGraphEdge, FlowGraphNode
from binaryninja.interaction import (
    MessageBoxButtonResult,
    MessageBoxButtonSet,
    MessageBoxIcon,
    show_message_box,
)
from binaryninjaui import (
    ContextMenuManager,
    DockContextHandler,
    FlowGraphWidget,
    Menu,
    UIActionContext,
    UIActionHandler,
    ViewFrame,
)
from PySide2.QtCore import QEvent, QObject, Qt
from PySide2.QtGui import QContextMenuEvent, QMouseEvent
from PySide2.QtWidgets import QVBoxLayout, QWidget

from .types import (
    BINARYNINJAUI_CUSTOM_EVENT,
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

VERBOSE = False

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
        return (
            BranchType.UserDefinedBranch,
            EdgeStyle(style=EdgePenStyle.DotLine, theme_color=ThemeColor.UnconditionalBranchColor))

    return {
        'TrueBranch': (BranchType.TrueBranch, None),
        'FalseBranch': (BranchType.FalseBranch, None),
        'UnconditionalBranch': (BranchType.UnconditionalBranch, None),
    }[edge['branchType']]


def is_conditional_edge(edge: FlowGraphEdge) -> bool:
    conditional_types = ('TrueBranch', 'FalseBranch', BranchType.TrueBranch, BranchType.FalseBranch)
    return edge.type in conditional_types


def is_call_node(node: CfNode) -> bool:
    return node['tag'] == 'Call'


def format_block_header(node: CfNode) -> str:
    node_id = node['contents']['uuid']
    node_tag = node['tag']

    if node_tag == 'BasicBlock':
        node_contents = cast(BasicBlockNode, node['contents'])
        return f'{node_contents["start"]:#x} (id {node_id}) BasicBlockNode' if VERBOSE else f'{node_contents["start"]:#x}'

    if node_tag == 'Call':
        node_contents = cast(CallNode, node['contents'])
        return f'{node_contents["start"]:#x} (id {node_id}) CallNode' if VERBOSE else f'{node_contents["start"]:#x} Call'

    if node_tag == 'EnterFunc':
        node_contents = cast(EnterFuncNode, node['contents'])
        prevFun = node_contents['prevCtx']['func']['name']
        nextFun = node_contents['nextCtx']['func']['name']
        return f'(id {node_id}) EnterFuncNode {prevFun} -> {nextFun}' if VERBOSE else f'Enter {prevFun} -> {nextFun}'

    if node_tag == 'LeaveFunc':
        node_contents = cast(LeaveFuncNode, node['contents'])
        prevFun = node_contents['prevCtx']['func']['name']
        nextFun = node_contents['nextCtx']['func']['name']
        return f'(id {node_id}) LeaveFuncNode {nextFun} <- {prevFun}' if VERBOSE else f'Leave {nextFun} <- {prevFun}'

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
    def nodes(self) -> Dict[UUID, CfNode]:
        return self.pil_icfg['nodes']

    @property
    def edges(self) -> List[CfEdge]:
        return self.pil_icfg['edges']

    def get_edge(self, source_id: str = None, dest_id: str = None) -> Optional[CfEdge]:
        for edge in self.edges:
            if (source_id is None or edge['src']['contents']['uuid'] == source_id) and \
               (dest_id is None or edge['dst']['contents']['uuid'] == dest_id):
                return edge

        return None

    def get_edges_from(self, source_id: str) -> List[CfEdge]:
        return [edge for edge in self.edges if source_id == edge['src']['contents']['uuid']]


class ICFGWidget(FlowGraphWidget, QObject):
    def __init__(self, parent: QWidget, view_frame: ViewFrame, blaze_instance: 'BlazeInstance'):
        FlowGraphWidget.__init__(self, parent, blaze_instance.bv)
        self._view_frame: ViewFrame = view_frame
        self.blaze_instance: 'BlazeInstance' = blaze_instance

        self.action_handler = UIActionHandler()
        self.action_handler.setupActionHandler(self)
        self.context_menu = Menu()
        self.context_menu_manager = ContextMenuManager(self)

        self.clicked_node: Optional[FlowGraphNode] = None
        self.clicked_edge: Optional[FlowGraphEdge] = None

        # Node ID which, once we get a new ICFG back, we should recenter on
        self.recenter_node_id: Optional[UUID] = None

        # Bind actions to their callbacks
        # yapf: disable
        actions: List[BNAction] = [
            BNAction(
                'Blaze', 'Prune', MenuOrder.FIRST,
                activate=self.context_menu_action_prune,
                isValid=
                    lambda ctx: self.clicked_edge is not None
                        and is_conditional_edge(self.clicked_edge),
            ),
            BNAction(
                'Blaze', 'Focus', MenuOrder.EARLY,
                activate=self.context_menu_action_focus,
                isValid=lambda ctx: self.clicked_node is not None
            ),
            BNAction(
                'Blaze', 'Expand Call Node', MenuOrder.EARLY,
                activate=self.context_menu_action_expand_call,
                isValid=self._clicked_node_is_call_node,
            ),
        ]
        # yapf: enable

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

    def customEvent(self, event: QEvent) -> None:
        FlowGraphWidget.customEvent(self, event)
        if event.type() != BINARYNINJAUI_CUSTOM_EVENT or self.recenter_node_id is None:
            return

        log.debug(f'Recentering on UUID {self.recenter_node_id!r}')
        for fg_node, cf_node in self.blaze_instance.graph.node_mapping.items():
            if cf_node['contents']['uuid'] == self.recenter_node_id:
                log.debug('Found recenter node\n%s', '\n'.join(map(str, fg_node.lines)))
                # time.sleep(self.sleep_time)
                self.showNode(fg_node)
                break
        else:
            log.error('Recenter node was deleted')
            return

    def expand_call(self, node: CallNode):
        '''
        Send a request to the backend that the `CallNode` `node` be expanded
        '''

        call_node = node.copy()
        call_node['nodeData'] = []
        self.blaze_instance.send(
            BinjaToServer(
                tag='BSCfgExpandCall',
                cfgId=self.blaze_instance.graph.pil_icfg_id,
                callNode=call_node))

    def context_menu_action_prune(self, context: UIActionContext):
        '''
        Context menu action to call `self.prune`. Assumes `self.clicked_edge` has already
        been set by `self.mousePressEvent`
        '''

        if self.clicked_edge is None:
            log.error('Did not right-click on an edge')
            return

        if not is_conditional_edge(self.clicked_edge):
            log.error('Not a conditional branch')
            return

        source_node = self.get_cf_node(self.clicked_edge.source)
        dest_node = self.get_cf_node(self.clicked_edge.target)
        if source_node is None or dest_node is None:
            raise RuntimeError('Missing node in node_mapping!')

        edge = self.blaze_instance.graph.get_edge(
            source_node['contents']['uuid'], dest_node['contents']['uuid'])
        if not edge:
            raise RuntimeError('Missing edge!')

        log.debug(
            'Double click on %s edge from %s to %s',
            'True' if edge['branchType'] == 'TrueBranch' else 'False',
            source_node['contents']['uuid'], dest_node['contents']['uuid'])

        self.recenter_node_id = source_node['contents']['uuid']

        from_node = edge['src']
        to_node = edge['dst']

        # 1. check if there exists a paired conditional branch

        # this must be a list of len 1 or 2, because the edge we're looking
        # at must be a conditional, and it must exist itself
        #   if len == 2, there is another conditional and we can carry on
        #   if len == 1, this is the only remaining conditional and we want to verify its deletion
        edges_from_source: List[CfEdge] = \
            self.blaze_instance.graph.get_edges_from(from_node['contents']['uuid'])

        if len(edges_from_source) == 1:
            # verify the only node is ourself, for sanity
            if edges_from_source[0]['dst']['contents']['uuid'] != to_node['contents']['uuid']:
                raise RuntimeError("I don't exist!")  # XXX uh oh! ... better msg needed

            # 2. popup modal
            # binaryninja.interaction.show_message_box
            to_continue: Optional[MessageBoxButtonResult] = show_message_box(
                "Blaze",
                "Pruning an isolated conditional branch! This will remove all nodes only reachable from this edge. Continue?",
                buttons=MessageBoxButtonSet.YesNoButtonSet,
                icon=MessageBoxIcon.WarningIcon)

            # 3. if cancel, return
            if to_continue == MessageBoxButtonResult.NoButton:
                return

        self.prune(from_node, to_node)

    def context_menu_action_focus(self, context: UIActionContext) -> None:
        '''
        Context menu action to call `self.focus`. Assumes `self.clicked_node` has already
        been set by `self.mousePressEvent`
        '''

        # FIXME implement focus
        log.warn('Focus is not implemented yet')

    def context_menu_action_expand_call(self, context: UIActionContext):
        '''
        Context menu action to call `self.expand_call`. Assumes `self.clicked_node` has already
        been set by `self.mousePressEvent`
        '''

        if not self.clicked_node:
            log.error(f'Did not right-click on a CFG node')
            return

        node = self.get_cf_node(self.clicked_node)
        if not node or not is_call_node(node):
            log.error(f'Did not right-click on a Call node')
            return

        self.recenter_node_id = node['contents']['uuid']

        call_node = cast(CallNode, node['contents'])
        self.expand_call(call_node)

    def mouseDoubleClickEvent(self, event: QMouseEvent) -> None:
        '''
        Expand the call node under mouse, if any
        '''

        if event.button() != Qt.LeftButton or self.blaze_instance.graph is None:
            return super().mousePressEvent(event)

        if (fg_node := self.getNodeForMouseEvent(event)):
            node = self.get_cf_node(fg_node)

            if not node:
                log.error(f'Couldn\'t find node_mapping[{fg_node}]')
                return

            if not is_call_node(node):
                log.warning('Did not double-click on a call node')
                return

            self.recenter_node_id = node['contents']['uuid']

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

        if self.blaze_instance.graph is None:
            log.info('Right-click in ICFG widget, but no ICFG was created')
            return

        self.clicked_node = self.getNodeForMouseEvent(event)
        if (fg_edge := self.getEdgeForMouseEvent(event)):
            fg_edge, swapped = fg_edge
            self.clicked_edge = fix_flowgraph_edge(fg_edge, swapped)
        else:
            self.clicked_edge = None

        self.context_menu_manager.show(self.context_menu, self.action_handler)

    def notifyInstanceChanged(self, blaze_instance: 'BlazeInstance', view_frame: ViewFrame):
        self.blaze_instance = blaze_instance
        self._view_frame = view_frame

    def notifyOffsetChanged(self, view_frame: ViewFrame, offset: int) -> None:
        pass

    def get_cf_node(self, node: FlowGraphNode) -> Optional[CfNode]:
        return self.blaze_instance.graph.node_mapping.get(node)

    def _clicked_node_is_call_node(self, ctx: UIActionContext) -> bool:
        '''
        Helper function for checking if the node just clicked is a call node
        Used for context menu validation
        '''
        valid = isinstance(self.clicked_node, FlowGraphNode)
        if valid:
            cf_node = self.get_cf_node(self.clicked_node)
            valid = cf_node is not None and is_call_node(cf_node)
        return valid


class ICFGDockWidget(QWidget, DockContextHandler):
    def __init__(
            self, name: str, view_frame: ViewFrame, parent: QWidget,
            blaze_instance: 'BlazeInstance'):
        QWidget.__init__(self, parent)
        DockContextHandler.__init__(self, self, name)

        self._view_frame: ViewFrame = view_frame
        self.blaze_instance: Optional['BlazeInstance'] = blaze_instance
        self.icfg_widget: ICFGWidget = ICFGWidget(self, view_frame, self.blaze_instance)

        # TODO why does pyright choke on these? Idea: they're both @typing.overload
        # And the overload that we want is the first one, but pyright only seems to
        # see the second one
        layout = QVBoxLayout()  # type: ignore
        layout.setContentsMargins(0, 0, 0, 0)  # type: ignore
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
