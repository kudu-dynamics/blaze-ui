import logging as _logging
from copy import deepcopy
import enum
from typing import TYPE_CHECKING, Container, Dict, List, Mapping, Optional, Tuple, cast

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
from binaryninja.highlight import HighlightColor
from binaryninja.interaction import (
    AddressField,
    MessageBoxButtonResult,
    MessageBoxButtonSet,
    MessageBoxIcon,
    TextLineField,
    get_form_input,
    show_message_box,
)
from binaryninjaui import (
    ContextMenuManager,
    DockContextHandler,
    FlowGraphWidget,
    HighlightTokenState,
    Menu,
    UIActionContext,
    UIActionHandler,
    ViewFrame,
)
from PySide6.QtCore import QEvent, QObject, Qt
from PySide6.QtGui import QContextMenuEvent, QMouseEvent
from PySide6.QtWidgets import QGridLayout, QLabel, QPushButton, QVBoxLayout, QWidget

from .types import (
    BINARYNINJAUI_CUSTOM_EVENT,
    UUID,
    Address,
    BasicBlockNode,
    BinjaToServer,
    CallDest,
    CallNode,
    CallNodeRating,
    CfEdge,
    Cfg,
    CfgId,
    CfNode,
    ConstFuncPtrOp,
    ConstraintBinjaToServer,
    EnterFuncNode,
    Function,
    GroupingNode,
    GroupOptions,
    LeaveFuncNode,
    PendingChanges,
    PoiBinjaToServer,
    PoiSearchResults,
    ServerCfg,
    SnapshotBinjaToServer,
    Word64,
    tokens_from_server,
)
from .util import (
    BNAction,
    add_actions,
    bind_actions,
    fix_flowgraph_edge,
    get_sections_at,
    try_debug,
)

if TYPE_CHECKING:
    from .client_plugin import BlazeInstance

VERBOSE = False

log = _logging.getLogger(__name__)


def muted_color(muteness: float, color: HighlightStandardColor) -> HighlightColor:
    "Mutes a color. 0.0 muteness is totally black. 1.0 is totally color"
    return HighlightColor(
        HighlightStandardColor.BlackHighlightColor,
        color,
        mix=int(min(255, max(0, muteness * 255))))


REGULAR_CALL_NODE_COLOR = muted_color(0.8, HighlightStandardColor.YellowHighlightColor)
POI_PRESENT_TARGET_COLOR = HighlightColor(HighlightStandardColor.WhiteHighlightColor)
POI_NODE_NOT_FOUND_COLOR = muted_color(0.4, HighlightStandardColor.YellowHighlightColor)
POI_UNREACHABLE_COLOR = HighlightColor(HighlightStandardColor.BlackHighlightColor)
POI_REACHABLE_MEH_COLOR_BASE = HighlightStandardColor.YellowHighlightColor
POI_REACHABLE_GOOD_COLOR_BASE = HighlightStandardColor.RedHighlightColor


def cfg_from_server(cfg: ServerCfg) -> Cfg:
    nodes = {k['contents']['uuid']: v for k, v in cfg['transportNodes']}
    return Cfg(nodes=nodes, edges=cfg['transportEdges'], root=cfg['transportRoot']['contents']['uuid'])


def cfg_to_server(cfg: Cfg) -> ServerCfg:
    nodes = [(cfg['nodes'][k], v) for k, v in cfg['nodes'].items()]
    return ServerCfg(transportNodes=nodes, transportEdges=cfg['edges'], transportRoot=cfg['nodes'][cfg['root']])


def get_edge_style(
    edge: CfEdge,
    nodes: Mapping[UUID, CfNode],
    removed_edges: Container[Tuple[UUID, UUID]],
) -> EdgeStyle:
    node_from = nodes[edge['src']['contents']['uuid']]

    color = {
        'TrueBranch': ThemeColor.TrueBranchColor,
        'FalseBranch': ThemeColor.FalseBranchColor,
        'UnconditionalBranch': ThemeColor.UnconditionalBranchColor,
    }[edge['branchType']]

    this_edge_uuids = (edge['src']['contents']['uuid'], edge['dst']['contents']['uuid'])

    if this_edge_uuids in removed_edges:
        edge_style = EdgeStyle(EdgePenStyle.DotLine, width=4, theme_color=color)
    elif node_from['tag'] == 'Call':
        edge_style = EdgeStyle(EdgePenStyle.DotLine, width=1, theme_color=color)
    else:
        edge_style = EdgeStyle(EdgePenStyle.SolidLine, width=1, theme_color=color)

    return edge_style

def is_basic_node(node: CfNode) -> bool:
    return node['tag'] == 'BasicBlock'

def is_grouping_node(node: CfNode) -> bool:
    return node['tag'] == 'Grouping'

def is_call_node(node: CfNode) -> bool:
    return node['tag'] == 'Call'


def is_indirect_call(call_node: CallNode) -> bool:
    return call_node['callDest']['tag'] == 'CallExpr'


def is_plt_call_node(bv: BinaryView, call_node: CallNode) -> bool:
    if call_node['callDest']['tag'] == 'CallFunc':
        func = cast(Function, call_node['callDest']['contents'])
        in_plt = any(
            sec.name in ('.plt', '.plt.got', '.plt.sec')
            for sec in get_sections_at(bv, func['address']))
        return in_plt
    else:
        return False


def is_got_call_node(bv: BinaryView, call_node: CallNode) -> bool:
    if call_node['callDest']['tag'] == 'CallAddr':
        func_ptr = cast(ConstFuncPtrOp, call_node['callDest']['contents'])
        in_got = any(
            sec.name in ('.got', '.got.plt', '.got.sec')
            for sec in get_sections_at(bv, func_ptr['address']))
        return in_got
    else:
        return False


def is_extern_call_node(call_node: CallNode) -> bool:
    return call_node['callDest']['tag'] == 'CallExtern'


def is_expandable_call_node(bv: BinaryView, call_node: CallNode) -> bool:
    return not is_plt_call_node(bv, call_node) and not is_got_call_node(
        bv, call_node) and not is_extern_call_node(call_node)

# TODO: Need to add Summary node
def is_group_start_node(node: CfNode) -> bool:
    return (is_call_node(node) or
            is_basic_node(node) or
            is_grouping_node(node))


def is_group_end_node(node: CfNode) -> bool:
    return is_group_start_node(node)


def get_target_address(call_dest: CallDest) -> Optional[Address]:
    dest_tag = call_dest['tag']
    if dest_tag == 'CallAddr':
        func_ptr = cast(ConstFuncPtrOp, call_dest['contents'])
        return func_ptr['address']
    elif dest_tag == 'CallFunc':
        func = cast(Function, call_dest['contents'])
        return func['address']
    else:
        return None


def node_contains_addr(node: CfNode, addr: Address) -> bool:
    tag = node['tag']
    if tag in ('EnterFunc', 'LeaveFunc'):
        return False
    elif tag == 'BasicBlock':
        basic_node = cast(BasicBlockNode, node['contents'])
        return (addr >= basic_node['start'] and addr <= basic_node['end'])
    elif tag == 'Call':
        call_node = cast(CallNode, node['contents'])
        return call_node['start'] == addr
    else:
        assert False, f'Inexaustive match on CfNode? tag={node["tag"]}'


def call_node_rating_color(rating: CallNodeRating) -> HighlightColor:
    if rating['tag'] == 'Unreachable':
        return POI_UNREACHABLE_COLOR

    elif rating['tag'] == 'Reachable':
        score = cast(float, rating.get('score'))
        return HighlightColor(
            POI_REACHABLE_MEH_COLOR_BASE,
            POI_REACHABLE_GOOD_COLOR_BASE,
            mix=int(min(255, max(0, score * 255))))

    else:
        assert False, f'Inexaustive match on CallNodeRating? tag={rating["tag"]}'


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

    elif node_tag == 'Grouping':
        node_contents = cast(GroupingNode, node['contents'])
        tokens = [
            InstructionTextToken(
                InstructionTextTokenType.TextToken,
                'Grouping',
            ),
        ]


    else:
        assert False, f'Inexaustive match on CFNode? tag={node["tag"]}'

    return DisassemblyTextLine(tokens)


def export_cfg_to_python(cfg: Cfg) -> str:
    '''
    Exports `cfg` to python code which draws `cfg` using the binaryninja.flowgraph API
    TODO: add flags that preserve node bodies' text, block highlights, edge types

    Example:

    >>> print(
    ...     blaze.cfg.export_cfg_to_python(
    ...         blaze.client_plugin.blaze.instances[bv_key(bv)].graph.pil_icfg))
    '''
    def idf(n: CfNode) -> str:
        s = n["contents"].get("start")
        if s is not None:
            return hex(s)[2:] + ('_call' if n['tag'] == 'Call' else '')
        else:
            return n["contents"]["uuid"].replace('-', '_')

    lines = [
        'from binaryninja.enums import BranchType',
        'from binaryninja.flowgraph import FlowGraph, FlowGraphNode',
        'from binaryninja.interaction import show_graph_report',
        '',
        'g = FlowGraph()',
        '',
        '',
        'def node(name):',
        '    n = FlowGraphNode(g)',
        '    n.lines = [name]',
        '    g.append(n)',
        '    return n',
        '',
        '',
        'def edge(a, b):',
        '    a.add_outgoing_edge(BranchType.UnconditionalBranch, b)',
        '',
        '',
    ]

    for (node_id, node) in cfg['nodes'].items():
        lines.append(f'node_{idf(node)} = node({idf(node)!r})')

    lines.append('')

    for edge in cfg['edges']:
        from_id = idf(edge['src'])
        to_id = idf(edge['dst'])
        lines.append(f'edge(node_{from_id}, node_{to_id})')

    lines.append('')
    lines.append('show_graph_report("Blaze ICFG", g)')

    return '\n'.join(lines)


class ICFGFlowGraph(FlowGraph):
    def __init__(
        self,
        bv: BinaryView,
        cfg: Cfg,
        cfg_id: CfgId,
        poi_search_results: Optional[PoiSearchResults],
        pending_changes: PendingChanges,
        group_options: Optional[GroupOptions]
    ):
        super().__init__()
        self.bv: BinaryView = bv
        self.pil_icfg: Cfg = cfg
        self.pil_icfg_id: CfgId = cfg_id
        self.node_mapping: Dict[FlowGraphNode, CfNode] = {}
        self.poi_search_results: Optional[PoiSearchResults] = poi_search_results
        self.pending_changes: PendingChanges = pending_changes
        self.group_options: Optional[GroupOptions] = group_options

        self.format()

        log.debug('Initialized object: %r', self)

    def __del__(self):
        try_debug(log, 'Deleting object: %r', self)

    def format(self):
        nodes: Dict[UUID, FlowGraphNode] = {}
        self.node_mapping = {}

        # Root node MUST be added to the FlowGraph first, otherwise weird FlowGraphWidget
        # layout issues may ensue
        source_nodes: List[Tuple[UUID, CfNode]]
        source_nodes = [(self.pil_icfg['root'],
                         self.pil_icfg['nodes'][self.pil_icfg['root']])]
        source_nodes += [(k, v)
                         for (k, v) in self.pil_icfg['nodes'].items()
                         if k != self.pil_icfg['root']]

        for (node_id, node) in source_nodes:
            fg_node = FlowGraphNode(self)
            self.node_mapping[fg_node] = node

            fg_node.lines = [format_block_header(node)]
            if node['contents'].get('nodeData'):
                tokenized_lines = node['contents']['nodeData']
                fg_node.lines += [tokens_from_server(line) for line in tokenized_lines]

            # TODO: Make use of view "modes" to detangle this complex if-else-if chain
            #       that is checking conditions of individual nodes as well as modes
            #       through the presence of non-None attribute values.
            if node['contents']['uuid'] in self.pending_changes.removed_nodes:
                fg_node.highlight = HighlightStandardColor.RedHighlightColor
            elif (self.poi_search_results and
                  (node['contents']['uuid']
                   in self.poi_search_results['presentTargetNodes'])):
                fg_node.highlight = POI_PRESENT_TARGET_COLOR
            elif (self.group_options and
                  node['contents']['uuid'] in self.group_options.end_nodes):
                fg_node.highlight = HighlightColor(HighlightStandardColor.BlueHighlightColor)
            elif (self.group_options and
                  node['contents']['uuid'] == self.group_options.start_node):
                fg_node.highlight = HighlightColor(HighlightStandardColor.GreenHighlightColor)
            elif self.group_options:
                # Don't color any other nodes when selecting a group end node
                pass
            elif node['tag'] == 'Call':
                call_node = cast(CallNode, node['contents'])
                if is_expandable_call_node(self.bv, call_node):
                    if self.poi_search_results:
                        ratings = self.poi_search_results['callNodeRatings']
                        rating = ratings.get(call_node['uuid'])
                        if rating:
                            fg_node.highlight = call_node_rating_color(rating)
                        else:
                            fg_node.highlight = POI_NODE_NOT_FOUND_COLOR
                    else:
                        fg_node.highlight = REGULAR_CALL_NODE_COLOR
                else:
                    fg_node.highlight = HighlightStandardColor.BlackHighlightColor
            elif node['tag'] == 'EnterFunc':
                opacity = 0.8 if self.poi_search_results else 1.0
                fg_node.highlight = muted_color(opacity,
                                                HighlightStandardColor.GreenHighlightColor)
            elif node['tag'] == 'LeaveFunc':
                opacity = 0.8 if self.poi_search_results else 1.0
                fg_node.highlight = muted_color(opacity,
                                                HighlightStandardColor.BlueHighlightColor)
            elif node['tag'] == 'Grouping':
                fg_node.highlight = HighlightColor(HighlightStandardColor.MagentaHighlightColor)
            nodes[node_id] = fg_node
            self.append(fg_node)

        for edge in self.pil_icfg['edges']:
            edge_style = get_edge_style(edge,
                                        self.pil_icfg['nodes'],
                                        self.pending_changes.removed_edges)
            nodes[edge['src']['contents']['uuid']].add_outgoing_edge(
                BranchType.UserDefinedBranch,
                nodes[edge['dst']['contents']['uuid']],
                edge_style,
            )

    @property
    def nodes(self) -> Dict[UUID, CfNode]:
        return self.pil_icfg['nodes']

    @property
    def edges(self) -> List[CfEdge]:
        return self.pil_icfg['edges']

    def get_edge(
        self,
        source_id: Optional[str] = None,
        dest_id: Optional[str] = None,
    ) -> Optional[CfEdge]:
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
        self.clicked_line: Optional[DisassemblyTextLine] = None
        self.clicked_token: Optional[HighlightTokenState] = None

        # Node ID which, once we get a new ICFG back, we should recenter on
        self.recenter_node_id: Optional[UUID] = None

        # Bind actions to their callbacks
        actions: List[BNAction] = [
            BNAction(
                'Blaze\\ICFG\\Edit',
                'Prune',
                activate=self.context_menu_action_prune,
                is_valid=lambda ctx: self.clicked_edge is not None and self.is_conditional_edge(
                    self.clicked_edge),
            ),
            BNAction(
                'Blaze\\ICFG\\Edit',
                'Focus',
                activate=self.context_menu_action_focus,
                is_valid=lambda ctx: self.clicked_node is not None,
            ),
            BNAction(
                'Blaze\\ICFG\\Edit',
                'Expand Call Node',
                activate=self.context_menu_action_expand_call,
                is_valid=self._clicked_node_is_expandable_call_node,
            ),
            BNAction(
                'Blaze\\ICFG\\Edit',
                'Add Constraint',
                activate=self.context_menu_action_add_constraint,
                is_valid=lambda ctx: (
                    self.clicked_node is not None and
                    (cf_node := self.get_cf_node(self.clicked_node)) is not None and cf_node.get(
                        'tag') == 'BasicBlock'),
            ),
            BNAction(
                'Blaze\\ICFG\\Edit',
                'Add Comment',
                activate=self.context_menu_action_add_comment,
                is_valid=lambda ctx: self.clicked_node is not None,
            ),
            BNAction(
                'Blaze\\ICFG\\Group',
                'Select Group Start',
                activate=self.context_menu_action_select_group_start,
                is_valid=lambda ctx: (
                    self.clicked_node is not None and
                    (cf_node := self.get_cf_node(self.clicked_node)) is not None and
                    is_group_start_node(cf_node)),
            ),
            BNAction(
                'Blaze\\ICFG\\Group',
                'Expand Group',
                activate=self.context_menu_action_expand_group,
                is_valid=lambda ctx: (
                    self.clicked_node is not None and
                    (cf_node := self.get_cf_node(self.clicked_node)) is not None and
                    is_grouping_node(cf_node)),
            ),
            # TODO: Add back but only activate when in grouping mode.
            # BNAction(
            #     'Blaze\\ICFG\\Group',
            #     'Select Group End',
            #     activate=self.context_menu_action_select_group_end,
            #     is_valid=lambda ctx: (
            #         self.clicked_node is not None and
            #         (cf_node := self.get_cf_node(self.clicked_node)) is not None and
            #         is_group_end_node(cf_node)),
            # ),
            BNAction(
                'Blaze\\ICFG\\Misc',
                'Go to Address',
                activate=self.context_menu_action_go_to_address,
                is_valid=lambda ctx: self.has_icfg(),
            ),
            BNAction(
                'Blaze\\POI',
                'Deactivate POI',
                activate=self.context_menu_action_deactivate_poi,
                is_valid=lambda ctx: self.has_active_poi(),
            ),
            BNAction(
                'Blaze\\Snapshot',
                'Save ICFG Snapshot',
                activate=self.context_menu_action_save_icfg_snapshot,
                is_valid=lambda ctx: self.has_icfg(),
            ),
        ]

        bind_actions(self.action_handler, actions)
        add_actions(self.context_menu, actions)

        log.debug('Initialized object: %r', self)

    def __del__(self):
        try_debug(log, 'Deleting object: %r', self)

    class Mode(enum.Enum):
        '''
        The various modes supported by the ICFGWidget.
        '''
        STANDARD = 1
        DIFF = 2
        GROUP_SELECT = 3

    def is_conditional_edge(self, fg_edge: FlowGraphEdge) -> bool:
        if not self.blaze_instance.graph:
            return False

        source = self.get_cf_node(cast(FlowGraphNode, fg_edge.source))
        dest = self.get_cf_node(cast(FlowGraphNode, fg_edge.target))

        assert source and dest
        if not (edge := self.blaze_instance.graph.get_edge(
                source['contents']['uuid'],
                dest['contents']['uuid'],
        )):
            return False

        return edge['branchType'] in ('TrueBranch', 'FalseBranch')

    def save_icfg(self):
        assert self.blaze_instance.graph
        cfg_id = self.blaze_instance.graph.pil_icfg_id
        snapshot_msg = SnapshotBinjaToServer(tag='SaveSnapshot', cfgId=cfg_id)

        log.debug('Requesting backend save snapshot of %r', cfg_id)

        self.blaze_instance.send(BinjaToServer(tag='BSSnapshot', snapshotMsg=snapshot_msg))

    def deactivate_poi(self):
        assert self.blaze_instance.graph
        cfg_id = self.blaze_instance.graph.pil_icfg_id
        poi_msg = PoiBinjaToServer(tag='DeactivatePoiSearch', activeCfg=cfg_id)
        self.blaze_instance.send(BinjaToServer(tag='BSPoi', poiMsg=poi_msg))

    def add_constraint(self, node: CfNode, stmtIndex: Word64, expr: str) -> None:
        assert self.blaze_instance.graph

        node_uuid = node['contents']['uuid']
        self.recenter_node_id = node_uuid
        # Send constraint to server
        constraint_msg = ConstraintBinjaToServer(
            cfgId=self.blaze_instance.graph.pil_icfg_id,
            node=node_uuid,
            stmtIndex=stmtIndex,
            exprText=expr)
        self.blaze_instance.send(BinjaToServer(tag='BSConstraint', constraintMsg=constraint_msg))

    def add_comment(self, node: CfNode, stmtIndex: Word64, comment: str) -> None:
        assert self.blaze_instance.graph

        node_uuid = node['contents']['uuid']
        self.recenter_node_id = node_uuid
        # Send constraint to server
        self.blaze_instance.send(
            BinjaToServer(
                tag='BSComment',
                cfgId=self.blaze_instance.graph.pil_icfg_id,
                nodeId=node_uuid,
                stmtIndex=stmtIndex,
                comment=comment,
            ))

    def select_group_start(self, start_node: CfNode) -> None:
        assert self.blaze_instance.graph

        start_uuid = start_node['contents']['uuid']
        self.recenter_node_id = start_uuid
        # Send start node to server
        self.blaze_instance.send(
            BinjaToServer(
                tag='BSGroupStart',
                cfgId=self.blaze_instance.graph.pil_icfg_id,
                startNodeId=start_uuid,
            ))

    def select_group_end(self, end_node: CfNode) -> None:
        assert self.blaze_instance.graph is not None

        if self.blaze_instance.graph.group_options:
            start_uuid = self.blaze_instance.graph.group_options.start_node
            end_uuid = end_node['contents']['uuid']
            self.recenter_node_id = start_uuid
            # Send end node to server
            self.blaze_instance.send(
                BinjaToServer(
                    tag='BSGroupDefine',
                    cfgId=self.blaze_instance.graph.pil_icfg_id,
                    startNodeId=start_uuid,
                    endNodeId=end_uuid
                ))

    def expand_group(self, grouping_node: CfNode) -> None:
        assert self.blaze_instance.graph

        grouping_uuid = grouping_node['contents']['uuid']
        self.recenter_node_id = grouping_uuid
        self.blaze_instance.send(
            BinjaToServer(
                tag='BSGroupExpand',
                cfgId=self.blaze_instance.graph.pil_icfg_id,
                groupingNodeId=grouping_uuid
            ))

    def prune(self, from_node: CfNode, to_node: CfNode):
        '''
        Send a request to the backend that the edge between `from_node` and
        `to_node` be pruned
        '''

        assert self.blaze_instance.graph

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


    def cancel_grouping(self) -> None:
        assert self.blaze_instance.graph is not None
        # Create a similar graph but without group_options
        # TODO: Do we need to update all other related instances too?
        graph = ICFGFlowGraph(self.blaze_instance.graph.bv,
                              self.blaze_instance.graph.pil_icfg,
                              self.blaze_instance.graph.pil_icfg_id,
                              self.blaze_instance.graph.poi_search_results,
                              self.blaze_instance.graph.pending_changes,
                              None)

        assert self.blaze_instance._icfg_dock_widget
        # TODO: Find a less hacky approach to accomplish this?
        self.blaze_instance._icfg_dock_widget.set_graph(graph)

    def customEvent(self, event: QEvent) -> None:
        FlowGraphWidget.customEvent(self, event)
        if event.type() != BINARYNINJAUI_CUSTOM_EVENT or self.recenter_node_id is None:
            return

        log.debug('Recentering on UUID %r', self.recenter_node_id)
        if not self.blaze_instance.graph:
            log.warning('No graph set')
            return

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

        assert self.blaze_instance.graph

        node = deepcopy(cf_node)
        node['contents']['nodeData'] = []
        self.blaze_instance.send(
            BinjaToServer(tag='BSCfgFocus', cfgId=self.blaze_instance.graph.pil_icfg_id, node=node))

    def expand_call(self, node: CallNode):
        '''
        Send a request to the backend that the `CallNode` `node` be expanded
        '''

        assert self.blaze_instance.graph

        call_node = node.copy()
        call_node['nodeData'] = []

        log.debug(
            'Requesting backend expand call-site at %s',
            call_node['start'],
            extra={'node_uuid': call_node['uuid']})

        if is_indirect_call(node):
            addr_field = AddressField('Function (start address or name)', self.blaze_instance.bv)
            if get_form_input([addr_field], 'Call Target'):
                target_addr = cast(int, addr_field.result)
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
        assert self.blaze_instance.graph

        if self.clicked_edge is None:
            log.error('Did not right-click on an edge')
            return

        if not self.is_conditional_edge(self.clicked_edge):
            log.error('Not a conditional branch')
            return

        source_node = self.get_cf_node(cast(FlowGraphNode, self.clicked_edge.source))
        dest_node = self.get_cf_node(cast(FlowGraphNode, self.clicked_edge.target))
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
            # FIXME: In BN 3.x this function now returns a MessageBoxButtonResultEnum instead of a
            #        MessageBoxButtonResult. This issue should be reported as it is likely a bug.
            #        For now we wrap with the Python constructor as a workaround.
            to_continue: Optional[MessageBoxButtonResult] = MessageBoxButtonResult(
                show_message_box(
                    "Blaze",
                    "Pruning an isolated conditional branch! This will remove all nodes only reachable from this edge. Continue?",
                    buttons=MessageBoxButtonSet.YesNoButtonSet,
                    icon=MessageBoxIcon.WarningIcon))

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

    def context_menu_action_deactivate_poi(self, context: UIActionContext):
        log.debug('Deactivating POI')
        self.deactivate_poi()

    def context_menu_action_go_to_address(self, context: UIActionContext):
        log.debug('Go to Address')
        # Get address from user
        addr_field = AddressField("Address:")
        confirm: bool = get_form_input([addr_field], 'Go to Address')
        if not confirm or not addr_field.result:
            return
        addr: Address = addr_field.result

        # Find node(s) containing address
        nodes = self.find_nodes_containing(addr)
        if not nodes:
            log.info(f'No nodes found containing address: 0x{addr:02x}')
            return

        # TODO: Select node if multiple matches
        target_cf_node: CfNode = nodes[0]

        # Recenter on node
        self.recenter_node_id = target_cf_node['contents']['uuid']

        if target_fg_node := self.get_fg_node(target_cf_node):
            self.showNode(target_fg_node)

    def context_menu_action_add_constraint(self, context: UIActionContext):
        log.debug('Add Constraint')

        # Get constraint from user
        text_field = TextLineField('Constraint:')
        confirm: bool = get_form_input([text_field], 'Add Constraint')
        if not confirm or not text_field.result:
            return
        text: str = text_field.result

        if not self.clicked_node:
            log.error(f'Did not right-click on a CFG node')
            return

        cf_node = self.get_cf_node(self.clicked_node)

        if not cf_node:
            log.error(f"Could not find matching CFG node")
            return

        self.add_constraint(cf_node, 0, text)

    def context_menu_action_add_comment(self, context: UIActionContext):
        log.debug('Add Comment')

        text_field = TextLineField('Comment:')
        confirm: bool = get_form_input([text_field], 'Add or Edit Comment')
        if not confirm:
            return

        comment: str = text_field.result or ''

        if not self.clicked_node:
            log.error(f'Did not right-click on a CFG node')
            return

        cf_node = self.get_cf_node(self.clicked_node)

        if not cf_node:
            log.error(f"Could not find matching CFG node")
            return

        self.add_comment(cf_node, 0, comment)

    def context_menu_action_select_group_start(self, context: UIActionContext):
        log.debug('Select Group Start')

        assert self.clicked_node is not None
        start_node = self.get_cf_node(self.clicked_node)
        assert start_node is not None

        # Send start_node to server
        self.select_group_start(start_node)

    def context_menu_action_expand_group(self, context: UIActionContext):
        log.debug('Expand Group')

        assert self.clicked_node is not None
        summary_node = self.get_cf_node(self.clicked_node)
        assert summary_node is not None

        self.expand_group(summary_node)

    def context_menu_action_select_group_end(self, context: UIActionContext):
        log.debug('Select Group End')

        assert self.clicked_node is not None
        end_node = self.get_cf_node(self.clicked_node)
        assert end_node is not None

        # Send start_node to server
        self.select_group_end(end_node)


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

            if (self.blaze_instance.graph.group_options and
                node['contents']['uuid'] in self.blaze_instance.graph.group_options.end_nodes):
                self.select_group_end(node)
                return

            if not is_call_node(node):
                log.warning('Did not double-click on a call node')
                return
            elif not (is_expandable_call_node(self.blaze_instance.bv, cast(CallNode,
                                                                         node['contents']))):
                log.warning('Call node not expandable')
                return
            else:
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

        # NOTE synthesize left mouse button click/release in order to highlight the
        # edge, line, or token under point
        super().mousePressEvent(
            QMouseEvent(
                QEvent.Type.MouseButtonPress,
                event.localPos(),
                event.windowPos(),
                event.globalPos(),
                Qt.MouseButton.LeftButton,
                Qt.MouseButtons(Qt.MouseButton.LeftButton),  # type: ignore
                Qt.KeyboardModifiers(),
                Qt.MouseEventSource.MouseEventSynthesizedByApplication,
                event.pointingDevice(),
            ))
        super().mouseReleaseEvent(
            QMouseEvent(
                QEvent.Type.MouseButtonRelease,
                event.localPos(),
                event.windowPos(),
                event.globalPos(),
                Qt.MouseButton.LeftButton,
                Qt.MouseButtons(Qt.MouseButton.LeftButton),  # type: ignore
                Qt.KeyboardModifiers(),
                Qt.MouseEventSource.MouseEventSynthesizedByApplication,
                event.pointingDevice(),
            ))

        if self.blaze_instance.graph is None:
            log.info('Right-click in ICFG widget, but no ICFG was created')
            return

        # self.clicked_node: Optional[FlowGraphNode] = self.getNodeForMouseEvent(event)
        self.clicked_node = self.getNodeForMouseEvent(event)

        # TODO: make hacky way to get clicked line
        # (getLineForMouseEvent is not implemented)
        # self.clicked_line = self.getLineForMouseEvent(event)

        self.clicked_token = self.getTokenForMouseEvent(event)

        if (event_edge := self.getEdgeForMouseEvent(event)):
            fg_edge, swapped = event_edge
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
        assert self.blaze_instance.graph is not None
        return self.blaze_instance.graph.node_mapping.get(node)

    def get_fg_node(self, node: CfNode) -> Optional[FlowGraphNode]:
        assert self.blaze_instance.graph is not None
        for fg_node, cf_node in self.blaze_instance.graph.node_mapping.items():
            if cf_node == node:
                return fg_node
        return None

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

    def find_nodes_containing(self, addr: Address) -> List[CfNode]:
        assert self.blaze_instance.graph
        return [
            node for node in self.blaze_instance.graph.nodes.values()
            if node_contains_addr(node, addr)
        ]

    def has_icfg(self) -> bool:
        return self.blaze_instance.graph != None

    def has_active_poi(self) -> bool:
        '''
        Check if there a POI displayed with the ICFG being displayed.
        '''
        if self.blaze_instance.graph:
            return self.blaze_instance.graph.poi_search_results != None
        else:
            return False


class ICFGToolbarWidget(QWidget):
    def __init__(
        self,
        parent: QWidget,
        icfg_widget: ICFGWidget,
        view_frame: ViewFrame,
        blaze_instance: 'BlazeInstance',
    ):
        QWidget.__init__(self, parent)
        self.icfg_widget: ICFGWidget = icfg_widget
        self._view_frame: ViewFrame = view_frame
        self.blaze_instance: 'BlazeInstance' = blaze_instance

        self.accept_button = QPushButton('Accept')
        self.accept_button.clicked.connect(self.accept)  # type: ignore
        self.reject_button = QPushButton('Reject')
        self.reject_button.clicked.connect(self.reject)  # type: ignore

        self.cancel_button = QPushButton('Cancel')
        self.cancel_button.clicked.connect(self.cancel)  # type: ignore

        self.simplification_stats_label = QLabel()
        self.update_stats(0, 0, 0, 0)

        layout = QGridLayout()
        layout.addWidget(self.accept_button, 0, 0, 1, 1)
        layout.addWidget(self.reject_button, 0, 1, 1, 1)
        layout.addWidget(self.cancel_button, 0, 2, 1, 1)
        layout.addWidget(
            self.simplification_stats_label, 0, 3, 1, 2,
            Qt.Alignment(Qt.AlignmentFlag.AlignRight))  # type: ignore
        self.setLayout(layout)

    def accept(self) -> None:
        log.debug('User accepted ICFG changes')
        if not self.blaze_instance.graph:
            log.warn('There is no graph associated with Blaze.')
        else:
            self.blaze_instance.send(
                BinjaToServer(
                    tag='BSCfgConfirmChanges',
                    cfgId=self.blaze_instance.graph.pil_icfg_id,
                ))

    def reject(self) -> None:
        # TODO send BSRejectIcfg message
        log.debug('User rejected ICFG changes')
        if not self.blaze_instance.graph:
            log.warn('There is no graph associated with Blaze.')
        else:
            self.blaze_instance.send(
                BinjaToServer(
                    tag='BSCfgRevertChanges',
                    cfgId=self.blaze_instance.graph.pil_icfg_id,
                ))

    def cancel(self) -> None:
        log.debug('User cancelled grouping')
        if not self.blaze_instance.graph:
            log.warn('There is no graph associated with Blaze.')
        else:
            self.blaze_instance.send(
                BinjaToServer(
                    tag='BSCfgRevertChanges',
                    cfgId=self.blaze_instance.graph.pil_icfg_id,
                ))

            # self.icfg_widget.cancel_grouping()

    def update_stats(
        self,
        nodes: int,
        edges: int,
        diff_nodes: int,
        diff_edges: int,
    ) -> None:
        s = ''
        if diff_nodes:
            s += f'Nodes: {nodes}{diff_nodes:+} = {nodes + diff_nodes}, '
        else:
            s += f'Nodes: {nodes}, '

        if diff_edges:
            s += f'Edges: {edges}{diff_edges:+} = {edges + diff_edges}'
        else:
            s += f'Edges: {edges}'

        self.simplification_stats_label.setText(s)


class ICFGDockWidget(QWidget, DockContextHandler):
    def __init__(
        self,
        name: str,
        view_frame: ViewFrame,
        parent: QWidget,
        blaze_instance: 'BlazeInstance',
    ):
        QWidget.__init__(self, parent)
        DockContextHandler.__init__(self, self, name)

        self._view_frame: ViewFrame = view_frame
        self.blaze_instance: 'BlazeInstance' = blaze_instance
        self.mode = ICFGWidget.Mode.STANDARD

        layout = QVBoxLayout()
        self.icfg_widget: ICFGWidget = ICFGWidget(self, view_frame, self.blaze_instance)
        self.icfg_toolbar_widget: ICFGToolbarWidget = ICFGToolbarWidget(
            self,
            self.icfg_widget,
            view_frame,
            self.blaze_instance,
        )
        self.icfg_toolbar_widget.accept_button.hide()
        self.icfg_toolbar_widget.reject_button.hide()
        self.icfg_toolbar_widget.cancel_button.hide()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addWidget(self.icfg_toolbar_widget)
        layout.addWidget(self.icfg_widget)
        self.setLayout(layout)

        log.debug('Initialized object: %r', self)

    def __del__(self):
        try_debug(log, 'Deleting object: %r', self)

    def set_graph(self, graph: ICFGFlowGraph):
        # Update mode
        if graph.pending_changes.has_changes:
            self.mode = ICFGWidget.Mode.DIFF
        elif graph.group_options:
            self.mode = ICFGWidget.Mode.GROUP_SELECT
        else:
            self.mode = ICFGWidget.Mode.STANDARD

        if self.mode == ICFGWidget.Mode.DIFF:
            self.icfg_toolbar_widget.accept_button.setVisible(True)
            self.icfg_toolbar_widget.reject_button.setVisible(True)
            self.icfg_toolbar_widget.cancel_button.setVisible(False)

            self.icfg_toolbar_widget.update_stats(
                nodes=len(graph.pil_icfg['nodes']),
                edges=len(graph.pil_icfg['edges']),
                diff_nodes=-len(graph.pending_changes.removed_nodes),
                diff_edges=-len(graph.pending_changes.removed_edges),
                )

        if self.mode == ICFGWidget.Mode.GROUP_SELECT:
            self.icfg_toolbar_widget.accept_button.setVisible(False)
            self.icfg_toolbar_widget.reject_button.setVisible(False)
            self.icfg_toolbar_widget.cancel_button.setVisible(True)

        if self.mode == ICFGWidget.Mode.STANDARD:
            self.icfg_toolbar_widget.accept_button.setVisible(False)
            self.icfg_toolbar_widget.reject_button.setVisible(False)
            self.icfg_toolbar_widget.cancel_button.setVisible(False)

        self.icfg_widget.setGraph(graph)

    def notifyViewChanged(self, view_frame: ViewFrame) -> None:
        log.debug('ViewFrame changed to %r', view_frame)
        self._view_frame = view_frame
        if view_frame is None:
            log.error('view_frame is None')
        else:
            view = view_frame.getCurrentViewInterface()
            self.blaze_instance = self.blaze_instance.blaze.ensure_instance(view.getData())
            self.icfg_widget.notifyInstanceChanged(self.blaze_instance, view_frame)

    def notifyOffsetChanged(self, offset: int) -> None:
        log.debug('offset changed (bv=%r, offset=%r)', self.blaze_instance.bv, offset)
        self.icfg_widget.notifyOffsetChanged(self._view_frame, offset)
