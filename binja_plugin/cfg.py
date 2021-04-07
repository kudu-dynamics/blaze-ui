import logging as _logging
from typing import Dict, TYPE_CHECKING, Optional, Tuple, Type, cast

from binaryninja import BinaryView
from binaryninja.enums import BranchType, EdgePenStyle, ThemeColor
from binaryninja.flowgraph import EdgeStyle, FlowGraph, FlowGraphNode
from binaryninja.function import Function
from binaryninjaui import DockContextHandler, FlowGraphWidget, ViewFrame
from PySide2.QtCore import QObject, Qt
from PySide2.QtGui import QMouseEvent
from PySide2.QtWidgets import QMessageBox, QVBoxLayout, QWidget

from .types import (
    Address,
    BasicBlockNode,
    CallNode,
    CfEdge,
    Cfg,
    CfNode,
    EnterFuncNode,
    LeaveFuncNode,
    ServerCfg,
    UUID,
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
        assert edge['branchType'] == 'UnconditionalBranch', 'bad assumption'
        return (BranchType.UserDefinedBranch,
                EdgeStyle(
                    style=EdgePenStyle.DashLine, theme_color=ThemeColor.UnconditionalBranchColor))

    if node_from['tag'] == 'LeaveFunc':
        assert edge['branchType'] == 'UnconditionalBranch', 'bad assumption'
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
    @classmethod
    def create(cls: Type['ICFGFlowGraph'], _bv: BinaryView, cfg: Cfg) -> 'ICFGFlowGraph':
        graph = cls()
        nodes: Dict[UUID, FlowGraphNode] = {}

        for (node_id, node) in cfg['nodes'].items():
            fg_node = FlowGraphNode(graph)

            fg_node.lines = [format_block_header(node)]
            if (nodeData := node.get('contents', {}).get('nodeData', None)):
                fg_node.lines += nodeData

            nodes[node_id] = fg_node
            graph.append(fg_node)

        for edge in cfg['edges']:
            branch_type, edge_style = get_edge_type(edge, cfg)
            nodes[edge['src']['contents']['uuid']].add_outgoing_edge(
                branch_type, nodes[edge['dst']['contents']['uuid']], edge_style)

        return graph


class Window(QMessageBox):
    def __init__(self, parent=None, text=None):
        super(Window, self).__init__(parent)

        self.setText(text or '')


class ICFGWidget(FlowGraphWidget, QObject):
    def __init__(self, parent: QWidget, view_frame: ViewFrame, blaze_instance: 'BlazeInstance'):
        FlowGraphWidget.__init__(self, parent, blaze_instance.bv, None)
        self._view_frame: ViewFrame = view_frame
        self.blaze_instance = blaze_instance
        self.graph: Optional[ICFGFlowGraph] = None

    def mouseDoubleClickEvent(self, event: QMouseEvent) -> None:
        parent = super()
        if event.button() != Qt.LeftButton:
            return parent.mousePressEvent(event)
        Window(None, 'Double!').exec_()

        # highlight_state = parent.getTokenForMouseEvent(event)
        # if highlight_state.addrValid and highlight_state.type == InstructionTextTokenType.CodeSymbolToken:
        #     function = self.blaze_instance.binary_view.get_function_at(
        #         highlight_state.addr, highlight_state.arch)
        #     Window(function.name).exec_()
        # else:
        #     Window(None, 'Double!').exec_()

    def notifyInstanceChanged(self, blaze_instance: 'BlazeInstance', view_frame: ViewFrame):
        self.blaze_instance = blaze_instance
        self._view_frame = view_frame

    def notifyOffsetChanged(self, view_frame: ViewFrame, offset: int) -> None:
        pass


class ICFGDockWidget(QWidget, DockContextHandler):
    def __init__(self, name: str, view_frame: ViewFrame, parent: QWidget, blaze: 'BlazePlugin',
                 blaze_instance: 'BlazeInstance'):
        QWidget.__init__(self, parent)
        DockContextHandler.__init__(self, self, name)

        self._view_frame: ViewFrame = view_frame
        self.blaze_instance: Optional['BlazeInstance'] = blaze_instance
        self.blaze: 'BlazePlugin' = blaze
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
            self.blaze_instance = self.blaze.ensure_instance(view.getData())
            self.icfg_widget.notifyInstanceChanged(self.blaze_instance, view_frame)

    def notifyOffsetChanged(self, offset: int) -> None:
        self.icfg_widget.notifyOffsetChanged(self._view_frame, offset)
