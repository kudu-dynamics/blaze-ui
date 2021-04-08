from copy import deepcopy
import json
import logging as _logging
import re
from typing import TYPE_CHECKING, Dict, Optional, Tuple, Type, cast

from binaryninja import BinaryView
from binaryninja.enums import BranchType, EdgePenStyle, HighlightStandardColor, InstructionTextTokenType, ThemeColor
from binaryninja.flowgraph import EdgeStyle, FlowGraph, FlowGraphNode
from binaryninjaui import DockContextHandler, FlowGraphWidget, ViewFrame
from PySide2.QtCore import QObject, Qt
from PySide2.QtGui import QMouseEvent
from PySide2.QtWidgets import QMessageBox, QVBoxLayout, QWidget

from .types import (
    BinjaToServer, CfgId, UUID,
    BasicBlockNode,
    CallNode,
    CfEdge,
    Cfg,
    CfNode,
    EnterFuncNode,
    LeaveFuncNode,
    ServerCfg,
)

if TYPE_CHECKING:
    from .client_plugin import BlazeInstance, BlazePlugin

log = _logging.getLogger(__name__)


def cfg_from_server(cfg: ServerCfg) -> Cfg:
    nodes = {k['contents']['uuid']: v for k, v in cfg['nodes']}
    return Cfg(nodes=nodes, edges=cfg['edges'], root=cfg['root']['contents']['uuid'])


def cfg_to_server(cfg: Cfg) -> ServerCfg:
    nodes = [(cfg['nodes'][k], v) for k, v in cfg['nodes'].items()]
    return ServerCfg(nodes=nodes, edges=cfg['edges'], root=cfg['nodes'][cfg['root']])


def get_edge_type(edge: CfEdge, cfg: Cfg) -> Tuple[BranchType, Optional[EdgeStyle]]:
    node_from = cfg['nodes'][edge['src']['contents']['uuid']]
    node_to = cfg['nodes'][edge['dst']['contents']['uuid']]

    if node_to['tag'] == 'EnterFunc':
        if edge['branchType'] != 'UnconditionalBranch':
            log.error('Bad assumption: edge was actually a %s', edge['branchType'])

        return (BranchType.UserDefinedBranch,
                EdgeStyle(
                    style=EdgePenStyle.DashLine, theme_color=ThemeColor.UnconditionalBranchColor))

    if node_from['tag'] == 'LeaveFunc':
        if edge['branchType'] != 'UnconditionalBranch':
            log.error('Bad assumption: edge was actually a %s', edge['branchType'])

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
    pil_icfg: Cfg
    pil_icfg_id: CfgId

    def __init__(self, _bv: BinaryView, cfg: Cfg, cfg_id: CfgId):
        super().__init__()
        self.pil_icfg = cfg
        self.pil_icfg_id = cfg_id

        nodes: Dict[UUID, FlowGraphNode] = {}

        for (node_id, node) in cfg['nodes'].items():
            fg_node = FlowGraphNode(self)

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


class ICFGWidget(FlowGraphWidget, QObject):
    def __init__(self, parent: QWidget, view_frame: ViewFrame, blaze_instance: 'BlazeInstance'):
        FlowGraphWidget.__init__(self, parent, blaze_instance.bv, None)
        self._view_frame: ViewFrame = view_frame
        self.blaze_instance: 'BlazeInstance' = blaze_instance
        self.graph: Optional[ICFGFlowGraph] = None

    def set_icfg(self, cfg_id: CfgId, cfg: Cfg):
        self.graph = ICFGFlowGraph(self.blaze_instance.bv, cfg, cfg_id)
        self.setGraph(self.graph)

    def mouseDoubleClickEvent(self, event: QMouseEvent) -> None:
        parent = super(ICFGWidget, self)
        # if event.button() != Qt.LeftButton or self.graph is None:
        if self.graph is None:
            return parent.mousePressEvent(event)

        # node = FlowGraphNode(self.graph)
        # res = parent.getNodeForMouseEvent(event, node)
        # res = self.getNodeForMouseEvent(event, node)
        # log.error(f'{res = }')
        # log.error(f'({node.x}, {node.y}): {node.lines}')

        highlight_state = parent.getTokenForMouseEvent(event)
        # if highlight_state.addrValid and highlight_state.type == InstructionTextTokenType.CodeSymbolToken:
        if highlight_state.type != InstructionTextTokenType.TextToken:
            log.error('unexpected highlight token type: %s. Trying anyway', highlight_state.type)

        line: str = highlight_state.token.text

        # Quick cheap hack until FlowGraphWidget.getNodeForMouseEvent works
        if not (m := re.search(r'\(id ([a-f0-9-]+)\)', line)):
            log.warn('Not a block header: %r', line)
            return

        uuid = m[1]
        node = self.graph.pil_icfg['nodes'][uuid]

        if line.endswith('CallNode'):
            call_node = cast(CallNode, node['contents']).copy()
            call_node['nodeData'] = []
            log.info(json.dumps(call_node, indent=2))
            self.blaze_instance.send(
                BinjaToServer(
                    tag='BSCfgExpandCall',
                    cfgId=self.graph.pil_icfg_id,
                    callNode=call_node
                ))

        elif event.button() == Qt.MouseButton.LeftButton:  # prune true branch
            for edge in self.graph.pil_icfg['edges']:
                if edge['src']['contents']['uuid'] == uuid and edge['branchType'] == 'TrueBranch':
                    break
            else:
                log.error('No True conditional branch from this node!')
                return

            from_node = deepcopy(edge['src'])
            to_node = deepcopy(edge['dst'])
            from_node['contents']['nodeData'] = []
            to_node['contents']['nodeData'] = []

            self.blaze_instance.send(
                BinjaToServer(
                    tag='BSCfgRemoveBranch',
                    cfgId=self.graph.pil_icfg_id,
                    edge=(from_node, to_node)
                ))
        else:  # prune false branch
            for edge in self.graph.pil_icfg['edges']:
                if edge['src']['contents']['uuid'] == uuid and edge['branchType'] == 'FalseBranch':
                    break
            else:
                log.error('No False conditional branch from this node!')
                return

            from_node = deepcopy(edge['src'])
            to_node = deepcopy(edge['dst'])
            from_node['contents']['nodeData'] = []
            to_node['contents']['nodeData'] = []

            self.blaze_instance.send(
                BinjaToServer(
                    tag='BSCfgRemoveBranch',
                    cfgId=self.graph.pil_icfg_id,
                    edge=(from_node, to_node)
                ))



    def notifyInstanceChanged(self, blaze_instance: 'BlazeInstance', view_frame: ViewFrame):
        self.blaze_instance = blaze_instance
        self._view_frame = view_frame

    def notifyOffsetChanged(self, view_frame: ViewFrame, offset: int) -> None:
        pass


class ICFGDockWidget(QWidget, DockContextHandler):
    def __init__(self, name: str, view_frame: ViewFrame, parent: QWidget, blaze_instance: 'BlazeInstance'):
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
