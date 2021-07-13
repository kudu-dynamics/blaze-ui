import logging as _logging
from copy import deepcopy
from typing import TYPE_CHECKING, Dict, List, Optional, Tuple, cast

import binaryninjaui
from binaryninja import BinaryView
from binaryninja.enums import (
    BranchType,
    EdgePenStyle,
    HighlightStandardColor,
    InstructionTextTokenType,
    ThemeColor,
)
from binaryninja.flowgraph import EdgeStyle, FlowGraph, FlowGraphEdge, FlowGraphNode
from binaryninja.function import DisassemblyTextLine, InstructionTextToken
from binaryninja.interaction import (
    AddressField,
    MessageBoxButtonResult,
    MessageBoxButtonSet,
    MessageBoxIcon,
    get_form_input,
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

if getattr(binaryninjaui, 'qt_major_version', None) == 6:
    from PySide6.QtCore import QEvent, QObject, Qt  # type: ignore
    from PySide6.QtGui import QContextMenuEvent, QMouseEvent  # type: ignore
    from PySide6.QtWidgets import QVBoxLayout, QWidget  # type: ignore
else:
    from PySide2.QtCore import QEvent, QObject, Qt  # type: ignore
    from PySide2.QtGui import QContextMenuEvent, QMouseEvent  # type: ignore
    from PySide2.QtWidgets import QVBoxLayout, QWidget  # type: ignore

from .types import (
    BINARYNINJAUI_CUSTOM_EVENT,
    UUID,
    Address,
    BasicBlockNode,
    BinjaToServer,
    CallDest,
    CallNode,
    CfEdge,
    Cfg,
    CfgId,
    CfNode,
    ConstFuncPtrOp,
    EnterFuncNode,
    Function,
    LeaveFuncNode,
    MenuOrder,
    ServerCfg,
    SnapshotBinjaToServer,
    tokens_from_server,
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


def is_indirect_call(call_node: CallNode) -> bool:
    return call_node['callDest']['tag'] == 'CallExpr'


def is_plt_call_node(bv: BinaryView, call_node: CallNode) -> bool:
    if call_node['callDest']['tag'] == 'CallFunc':
        func = cast(Function, call_node['callDest']['contents'])
        in_plt = any(
            [
                sec.name in ('.plt', '.plt.got', '.plt.sec')
                for sec in bv.get_sections_at(func['address'])
            ])
        return in_plt
    else:
        return False

def is_got_call_node(bv: BinaryView, call_node: CallNode) -> bool:
    if call_node['callDest']['tag'] == 'CallAddr':
        func_ptr = cast(ConstFuncPtrOp, call_node['callDest']['contents'])
        in_got = any(
            [
                sec.name in ('.got', '.got.plt', '.got.sec')
                for sec in bv.get_sections_at(func_ptr['address'])
            ])
        return in_got
    else:
        return False


def is_expandable_call_node(bv: BinaryView, call_node: CallNode) -> bool:
    return not is_plt_call_node(bv, call_node) and not is_got_call_node(bv, call_node)


def get_target_address(call_dest: CallDest) -> Optional[Address]:
    dest_tag = call_dest['tag']
    if dest_tag == 'CallAddr':
        return cast(Address, call_dest['contents'])
    elif dest_tag == 'CallFunc':
        func = cast(Function, call_dest['contents'])
        return func['address']
    else:
        return None


def format_block_header(node: CfNode) -> DisassemblyTextLine:
    node_id = node['contents']['uuid']
    node_tag = node['tag']

    tokens: List[InstructionTextToken]

    if node_tag == 'BasicBlock':
        node_contents = cast(BasicBlockNode, node['contents'])
        tokens = [
            InstructionTextToken(
                InstructionTextTokenType.PossibleAddressToken,
                hex(node_contents['start']),
                value=node_contents['start'],
            ),
        ]
        if VERBOSE:
            tokens += [
                InstructionTextToken(InstructionTextTokenType.TextToken, f' (id {node_id}) '),
                InstructionTextToken(InstructionTextTokenType.KeywordToken, 'BasicBlocknode'),
            ]

    elif node_tag == 'Call':
        node_contents = cast(CallNode, node['contents'])
        tokens = [
            InstructionTextToken(
                InstructionTextTokenType.PossibleAddressToken,
                hex(node_contents['start']),
                value=node_contents['start'],
            ),
        ]
        if VERBOSE:
            tokens += [
                InstructionTextToken(InstructionTextTokenType.TextToken, f' (id {node_id}) '),
                InstructionTextToken(InstructionTextTokenType.KeywordToken, 'CallNode'),
            ]

    elif node_tag == 'EnterFunc':
        node_contents = cast(EnterFuncNode, node['contents'])
        if VERBOSE:
            tokens = [
                InstructionTextToken(InstructionTextTokenType.TextToken, f'(id {node_id}) '),
                InstructionTextToken(InstructionTextTokenType.KeywordToken, 'EnterFuncNode '),
            ]
        else:
            tokens = [
                InstructionTextToken(InstructionTextTokenType.KeywordToken, 'Enter '),
            ]

        tokens += [
            InstructionTextToken(
                InstructionTextTokenType.CodeSymbolToken,
                node_contents['prevCtx']['func']['name'],
                value=node_contents['prevCtx']['func']['address'],
            ),
            InstructionTextToken(InstructionTextTokenType.TextToken, ' -> '),
            InstructionTextToken(
                InstructionTextTokenType.CodeSymbolToken,
                node_contents['nextCtx']['func']['name'],
                value=node_contents['nextCtx']['func']['address'],
            ),
        ]

    elif node_tag == 'LeaveFunc':
        node_contents = cast(LeaveFuncNode, node['contents'])
        if VERBOSE:
            tokens = [
                InstructionTextToken(InstructionTextTokenType.TextToken, f'(id {node_id}) '),
                InstructionTextToken(InstructionTextTokenType.KeywordToken, 'LeaveFuncNode '),
            ]
        else:
            tokens = [
                InstructionTextToken(InstructionTextTokenType.KeywordToken, 'Return '),
            ]

        tokens += [
            InstructionTextToken(
                InstructionTextTokenType.CodeSymbolToken,
                node_contents['nextCtx']['func']['name'],
                value=node_contents['nextCtx']['func']['address'],
            ),
            InstructionTextToken(InstructionTextTokenType.TextToken, ' <- '),
            InstructionTextToken(
                InstructionTextTokenType.CodeSymbolToken,
                node_contents['prevCtx']['func']['name'],
                value=node_contents['prevCtx']['func']['address'],
            ),
        ]

    else:
        assert False, f'Inexaustive match on CFNode? tag={node["tag"]}'

    return DisassemblyTextLine(tokens)


class ICFGFlowGraph(FlowGraph):
    def __init__(self, bv: BinaryView, cfg: Cfg, cfg_id: CfgId):
        super().__init__()
        self.pil_icfg: Cfg = cfg
        self.pil_icfg_id: CfgId = cfg_id
        self.node_mapping: Dict[FlowGraphNode, CfNode] = {}

        nodes: Dict[UUID, FlowGraphNode] = {}

        for (node_id, node) in cfg['nodes'].items():
            fg_node = FlowGraphNode(self)
            self.node_mapping[fg_node] = node

            fg_node.lines = [format_block_header(node)]
            tokenized_lines = node['contents']['nodeData']
            fg_node.lines += [tokens_from_server(line) for line in tokenized_lines]

            if node['tag'] == 'Call':
                if is_expandable_call_node(bv, cast(CallNode, node['contents'])):
                    fg_node.highlight = HighlightStandardColor.YellowHighlightColor
                else:
                    fg_node.highlight = HighlightStandardColor.BlackHighlightColor
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

        log.debug('%r initialized', self)

    def __del__(self):
        log.debug(f'Deleting {self!r}')

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
                isValid=self._clicked_node_is_expandable_call_node,
            ),
            BNAction(
                'Blaze', 'Save ICfg Snapshot', MenuOrder.EARLY,
                activate = self.context_menu_action_save_icfg_snapshot,
                # how would you check to see an icfg is loaded?
                isValid = lambda ctx: True,
            ),

        ]
        # yapf: enable

        bind_actions(self.action_handler, actions)
        add_actions(self.context_menu, actions)

        log.debug('%r initialized', self)

    def __del__(self):
        log.debug(f'Deleting {self!r}')

    def set_icfg(self, cfg_id: CfgId, cfg: Cfg):
        self.blaze_instance.graph = ICFGFlowGraph(self.blaze_instance.bv, cfg, cfg_id)
        self.setGraph(self.blaze_instance.graph)

    def save_icfg(self):
        cfg_id = self.blaze_instance.graph.pil_icfg_id
        snapshot_msg = SnapshotBinjaToServer(tag='SaveSnapshot', cfgId=cfg_id)

        log.debug('Requesting backend save snapshot of %r', cfg_id)

        self.blaze_instance.send(BinjaToServer(tag='BSSnapshot', snapshotMsg=snapshot_msg))

    def prune(self, from_node: CfNode, to_node: CfNode):
        '''
        Send a request to the backend that the edge between `from_node` and
        `to_node` be pruned
        '''

        from_node = deepcopy(from_node)
        to_node = deepcopy(to_node)
        from_node['contents']['nodeData'] = []
        to_node['contents']['nodeData'] = []

        log.debug(
            'Requesting backend prune edge from %r to %r',
            from_node['contents']['uuid'],
            to_node['contents']['uuid'],
        )

        self.blaze_instance.send(
            BinjaToServer(
                tag='BSCfgRemoveBranch',
                cfgId=self.blaze_instance.graph.pil_icfg_id,
                edge=(from_node, to_node)))

    def customEvent(self, event: QEvent) -> None:
        FlowGraphWidget.customEvent(self, event)
        if event.type() != BINARYNINJAUI_CUSTOM_EVENT or self.recenter_node_id is None:
            return

        log.debug('Recentering on UUID %r', self.recenter_node_id)
        for fg_node, cf_node in self.blaze_instance.graph.node_mapping.items():
            if cf_node['contents']['uuid'] == self.recenter_node_id:
                log.debug('Found recenter node', extra={'node': cf_node})
                self.showNode(fg_node)
                break
        else:
            log.error('Recenter node was deleted')
            return

    def focus(self, cf_node: CfNode):
        '''
        Send a request to the backend to focus on the `CfNode`
        '''

        node = deepcopy(cf_node)
        node['contents']['nodeData'] = []
        self.blaze_instance.send(
            BinjaToServer(tag='BSCfgFocus', cfgId=self.blaze_instance.graph.pil_icfg_id, node=node))

    def expand_call(self, node: CallNode):
        '''
        Send a request to the backend that the `CallNode` `node` be expanded
        '''

        call_node = node.copy()
        call_node['nodeData'] = []

        log.debug(
            'Requesting backend expand call-site at %s',
            call_node['start'],
            extra={'node': call_node})

        if is_indirect_call(node):
            addr_field = AddressField('Function (start address or name)', self.blaze_instance.bv)
            if get_form_input([addr_field], 'Call Target'):
                target_addr = addr_field.result
                self.blaze_instance.send(
                    BinjaToServer(
                        tag='BSCfgExpandCall',
                        cfgId=self.blaze_instance.graph.pil_icfg_id,
                        callNode=call_node,
                        targetAddress=target_addr))
        else:
            maybe_target_addr = get_target_address(call_node['callDest'])
            # This should never happen. Call nodes with indirect calls are handled differently.
            if maybe_target_addr is None:
                log.error(
                    'Could not get target address for call node at 0x%08x', call_node['start'])

            target_addr = cast(Address, maybe_target_addr)

            self.blaze_instance.send(
                BinjaToServer(
                    tag='BSCfgExpandCall',
                    cfgId=self.blaze_instance.graph.pil_icfg_id,
                    callNode=call_node,
                    targetAddress=target_addr))

    def context_menu_action_prune(self, context: UIActionContext):
        '''
        Context menu action to call `self.prune`. Assumes `self.clicked_edge` has already
        been set by `self.mousePressEvent`
        '''

        log.debug('User requested prune')

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

        log.debug('User requested focus')

        if not self.clicked_node:
            log.error(f'Did not right-click on a CFG node')
            return

        node = self.get_cf_node(self.clicked_node)
        if not node:
            log.error(f'Did not right-click on a node')
            return

        self.recenter_node_id = node['contents']['uuid']

        self.focus(node)

    def context_menu_action_expand_call(self, context: UIActionContext):
        '''
        Context menu action to call `self.expand_call`. Assumes `self.clicked_node` has already
        been set by `self.mousePressEvent`
        '''

        log.debug('User requested call-site expansion')

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

    def context_menu_action_save_icfg_snapshot(self, context: UIActionContext):
        log.debug('User requested Save ICFG')
        self.save_icfg()

    def mouseDoubleClickEvent(self, event: QMouseEvent) -> None:
        '''
        Expand the call node under mouse, if any
        '''

        log.debug('User double-clicked')

        if event.button() != Qt.LeftButton or self.blaze_instance.graph is None:
            return super().mousePressEvent(event)

        if (fg_node := self.getNodeForMouseEvent(event)):
            node = self.get_cf_node(fg_node)

            if not node:
                log.error('Couldn\'t find node_mapping[%r]', fg_node)
                return

            if not is_call_node(node):
                log.warning('Did not double-click on a call node')
                return

            if not (is_expandable_call_node(
                    self.blaze_instance.bv,
                    cast(CallNode, node['contents']))):
                log.warning('Call node not expandable')
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

        # self.clicked_node: Optional[FlowGraphNode] = self.getNodeForMouseEvent(event)
        self.clicked_node = self.getNodeForMouseEvent(event)

        if (fg_edge := self.getEdgeForMouseEvent(event)):
            fg_edge, swapped = fg_edge
            self.clicked_edge = fix_flowgraph_edge(fg_edge, swapped)
        else:
            self.clicked_edge = None

        self.context_menu_manager.show(self.context_menu, self.action_handler)

    def notifyInstanceChanged(self, blaze_instance: 'BlazeInstance', view_frame: ViewFrame):
        log.debug('Changing ICFG view to blaze instance %r', blaze_instance)
        self.blaze_instance = blaze_instance
        self._view_frame = view_frame

    def notifyOffsetChanged(self, view_frame: ViewFrame, offset: int) -> None:
        pass

    def get_cf_node(self, node: FlowGraphNode) -> Optional[CfNode]:
        return self.blaze_instance.graph.node_mapping.get(node)

    def _clicked_node_is_expandable_call_node(self, _ctx: UIActionContext) -> bool:
        '''
        Helper function for checking if the node just clicked is a call node
        Used for context menu validation
        '''
        if isinstance(self.clicked_node, FlowGraphNode):
            cf_node = self.get_cf_node(self.clicked_node)
            return (cf_node is not None and \
                    is_call_node(cf_node) and
                    is_expandable_call_node(
                        self.blaze_instance.bv,
                        cast(CallNode, cf_node['contents'])))
        return False


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

        log.debug('%r initialized', self)

    def __del__(self):
        log.debug(f'Deleting {self!r}')

    def notifyViewChanged(self, view_frame: ViewFrame) -> None:
        log.debug('ViewFrame changed to %r', view_frame)
        self._view_frame = view_frame
        if view_frame is None:
            self.blaze_instance = None
        else:
            view = view_frame.getCurrentViewInterface()
            self.blaze_instance = self.blaze_instance.blaze.ensure_instance(view.getData())
            self.icfg_widget.notifyInstanceChanged(self.blaze_instance, view_frame)

    def notifyOffsetChanged(self, offset: int) -> None:
        self.icfg_widget.notifyOffsetChanged(self._view_frame, offset)
