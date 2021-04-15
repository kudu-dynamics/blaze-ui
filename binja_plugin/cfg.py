import ctypes
import json
import logging as _logging
from copy import deepcopy
from typing import TYPE_CHECKING, Dict, Optional, Tuple, cast

from binaryninja import BinaryView
from binaryninja.enums import BranchType, EdgePenStyle, HighlightStandardColor, ThemeColor
from binaryninja.flowgraph import EdgeStyle, FlowGraph, FlowGraphNode
from binaryninjaui import DockContextHandler, FlowGraphWidget, ViewFrame
from PySide2.QtCore import QObject
from PySide2.QtGui import QMouseEvent
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
    ServerCfg,
)

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
        # FIXME change this to a Dict[FlowGraphNode, CfNode] once FlowGraphNode is hashable
        # (cf. https://github.com//binaryninja-api/pull/2376)
        self.node_mapping: Dict[int, CfNode] = {}

        nodes: Dict[UUID, FlowGraphNode] = {}

        for (node_id, node) in cfg['nodes'].items():
            fg_node = FlowGraphNode(self)
            # FIXME remove this once FlowGraphNode is hashable
            if not fg_node.handle:
                raise RuntimeError('FlowGraphNode has NULL .handle')

            self.node_mapping[ctypes.addressof(fg_node.handle.contents)] = node

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

    def set_icfg(self, cfg_id: CfgId, cfg: Cfg):
        self.blaze_instance.graph = ICFGFlowGraph(self.blaze_instance.bv, cfg, cfg_id)
        self.setGraph(self.blaze_instance.graph)

    def mouseDoubleClickEvent(self, event: QMouseEvent) -> None:
        parent = super(ICFGWidget, self)
        # if event.button() != Qt.LeftButton or self.blaze_instance.graph is None:
        if self.blaze_instance.graph is None:
            return parent.mousePressEvent(event)

        if (fg_node := self.getNodeForMouseEvent(event)):
            self.handle_node_double_click_event(event, fg_node)

        if (fg_edge := self.getEdgeForMouseEvent(event)):
            fg_edge, swapped = fg_edge
            if swapped:
                source, dest = fg_edge.target, fg_edge.source
            else:
                source, dest = fg_edge.source, fg_edge.target
            self.handle_edge_double_click_event(event, source, dest)

    def handle_node_double_click_event(self, event: QMouseEvent, fg_node: FlowGraphNode) -> None:
        fg_node_addr = ctypes.addressof(fg_node.handle.contents)
        node = self.blaze_instance.graph.node_mapping.get(fg_node_addr)

        if not node:
            log.warning(f'Couldn\'t find node_mapping[{fg_node_addr}]')
            return

        if node['tag'] != 'Call':
            log.warning('Did not double-click on a node')
            return

        call_node = cast(CallNode, node['contents']).copy()
        call_node['nodeData'] = []
        log.info(json.dumps(call_node, indent=2))
        self.blaze_instance.send(
            BinjaToServer(
                tag='BSCfgExpandCall',
                cfgId=self.blaze_instance.graph.pil_icfg_id,
                callNode=call_node))

    def handle_edge_double_click_event(
            self,
            event: QMouseEvent,
            source_fg_node: FlowGraphNode,
            dest_fg_node: FlowGraphNode) \
            -> None:

        source_node = self.blaze_instance.graph.node_mapping.get(ctypes.addressof(source_fg_node.handle.contents))
        dest_node = self.blaze_instance.graph.node_mapping.get(ctypes.addressof(dest_fg_node.handle.contents))
        if source_node is None or dest_node is None:
            raise RuntimeError('Missing node in node_mapping!')

        edge = self.blaze_instance.graph.get_edge(source_node['contents']['uuid'], dest_node['contents']['uuid'])
        if not edge:
            raise RuntimeError('Missing edge!')

        if edge['branchType'] not in ('TrueBranch', 'FalseBranch'):
            raise ValueError('Not a conditional branch')

        from_node = deepcopy(edge['src'])
        to_node = deepcopy(edge['dst'])
        from_node['contents']['nodeData'] = []
        to_node['contents']['nodeData'] = []

        self.blaze_instance.send(
            BinjaToServer(
                tag='BSCfgRemoveBranch',
                cfgId=self.blaze_instance.graph.pil_icfg_id,
                edge=(from_node, to_node)))

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
