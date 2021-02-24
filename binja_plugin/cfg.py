from binaryninja import PluginCommand, HighlightStandardColor, log_info, log_error, log_warn, BinaryView
from binaryninjaui import UIAction
from binaryninja.function import DisassemblyTextRenderer, InstructionTextToken
from binaryninja.flowgraph import FlowGraph, FlowGraphNode
from binaryninja.enums import InstructionTextTokenType, BranchType
from binaryninjaui import FlowGraphWidget, ViewType
from binaryninja.plugin import BackgroundTaskThread
from binaryninja.interaction import show_graph_report


# Basic sample flowgrpah
#
# Creates a flow graph, showing some basic functionality

def start_cfg(bv, func):
    graph = FlowGraph()
    node_a = FlowGraphNode(graph)
    node_a.lines = ["Node A"]
    node_b = FlowGraphNode(graph)
    node_b.lines = ["Node B"]
    node_c = FlowGraphNode(graph)
    node_c.lines = ["Node C"]
    graph.append(node_a)
    graph.append(node_b)
    graph.append(node_c)
    node_a.add_outgoing_edge(BranchType.UnconditionalBranch, node_b)
    node_a.add_outgoing_edge(BranchType.UnconditionalBranch, node_c)
    show_graph_report("In order", graph)

    graph2 = FlowGraph()
    node2_a = FlowGraphNode(graph)
    node2_a.lines = ["Node A"]
    node2_b = FlowGraphNode(graph)
    node2_b.lines = ["Node B"]
    node2_c = FlowGraphNode(graph)
    node2_c.lines = ["Node C"]
    graph2.append(node2_b)
    graph2.append(node2_c)
    graph2.append(node2_a)
    node2_a.add_outgoing_edge(BranchType.UnconditionalBranch, node2_b)
    node2_a.add_outgoing_edge(BranchType.UnconditionalBranch, node2_c)
    show_graph_report("Out of order", graph)
