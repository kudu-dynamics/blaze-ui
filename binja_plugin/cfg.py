import enum
import logging as _logging
from typing import TYPE_CHECKING, Any, Dict, Optional, Tuple, Type

from binaryninja import BinaryView
import binaryninja
from binaryninja.enums import BranchType, EdgePenStyle, InstructionTextTokenType, ThemeColor
from binaryninja.flowgraph import EdgeStyle, FlowGraph, FlowGraphNode
from binaryninjaui import DockContextHandler, FlowGraphWidget, ViewFrame
from PySide2.QtCore import QObject, Qt
from PySide2.QtGui import QMouseEvent
from PySide2.QtWidgets import QMessageBox, QVBoxLayout, QWidget

if TYPE_CHECKING:
    from .client_plugin import BlazeInstance, BlazePlugin

log = _logging.getLogger(__name__)


class CFNode(str, enum.Enum):
    BasicBlock = 'BasicBlock'
    Call = 'Call'
    EnterFunc = 'EnterFunc'
    LeaveFunc = 'LeaveFunc'


def get_edge_type(edge, nodes) -> Tuple[BranchType, Optional[EdgeStyle]]:
    node_from = nodes[edge['src']]
    node_to = nodes[edge['dst']]

    if node_to['tag'] == CFNode.EnterFunc:
        assert edge['branchType'] == 'UnconditionalBranch', 'bad assumption'
        return (BranchType.UserDefinedBranch,
                EdgeStyle(
                    style=EdgePenStyle.DashLine, theme_color=ThemeColor.UnconditionalBranchColor))

    if node_from['tag'] == CFNode.LeaveFunc:
        assert edge['branchType'] == 'UnconditionalBranch', 'bad assumption'
        return (BranchType.UserDefinedBranch,
                EdgeStyle(
                    style=EdgePenStyle.DotLine, theme_color=ThemeColor.UnconditionalBranchColor))

    return {
        'TrueBranch': (BranchType.TrueBranch, None),
        'FalseBranch': (BranchType.FalseBranch, None),
        'UnconditionalBranch': (BranchType.UnconditionalBranch, None),
    }[edge['branchType']]


def format_block_header(node_id: int, node: dict) -> str:
    tag = node['tag']
    start_addr = node['contents'].get('start', None)

    if tag == CFNode.BasicBlock:
        return f'{start_addr:#x} (id {node_id}) {tag}'

    if tag == CFNode.EnterFunc:
        prevFun = node['contents']['prevCtx']['func']['name']
        nextFun = node['contents']['nextCtx']['func']['name']
        return f'(id {node_id}) {tag} {prevFun} -> {nextFun}'

    if tag == CFNode.LeaveFunc:
        prevFun = node['contents']['prevCtx']['func']['name']
        nextFun = node['contents']['nextCtx']['func']['name']
        return f'(id {node_id}) {tag} {nextFun} <- {prevFun}'

    if tag == CFNode.Call:
        fun = node['contents']['function']['name']
        return f'{start_addr:#x} (id {node_id}) {tag} {fun}'

    assert False, f'Inexaustive match on CFNode? tag={tag}'


class ICFGFlowGraph(FlowGraph):
    @classmethod
    def create(cls: Type['ICFGFlowGraph'], _bv: BinaryView, cfg: Dict[str, Any]) -> 'ICFGFlowGraph':
        cfg = {**cfg, 'nodeMap': {k: v for [k, v] in cfg['nodeMap']}}

        graph = cls()
        nodes = {}

        for (node_id, node) in cfg['nodeMap'].items():
            fg_node = FlowGraphNode(graph)

            fg_node.lines = [format_block_header(node_id, node)]
            if (nodeData := node.get('contents', {}).get('nodeData', None)):
                fg_node.lines += nodeData

            nodes[node_id] = fg_node
            graph.append(fg_node)

        for edge in cfg['edges']:
            branch_type, edge_style = get_edge_type(edge, cfg['nodeMap'])
            nodes[edge['src']].add_outgoing_edge(branch_type, nodes[edge['dst']], edge_style)

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
