from typing import Dict, Any

from binaryninja import PluginCommand, HighlightStandardColor, log_info, log_error, log_warn, BinaryView
from binaryninjaui import UIAction
from binaryninja.function import DisassemblyTextRenderer, InstructionTextToken
from binaryninja.flowgraph import FlowGraph, FlowGraphNode, EdgeStyle
from binaryninja.enums import (BranchType, InstructionTextTokenType,
                               HighlightStandardColor, FlowGraphOption,
                               EdgePenStyle, ThemeColor)
from binaryninjaui import FlowGraphWidget, ViewType
from binaryninja.plugin import BackgroundTaskThread
from binaryninja.interaction import show_graph_report

example_graph = {
    'nodes': [
        {
            'id': 1,
            'lines': [
                'Branch cond: cmpE (rcx) (0)'
            ],
        },
        {
            'id': 2,
            'lines': [
                'rdi = rcx', \
                'call f f [0xdeadbeef]', \
                'enter context?',
            ],
        },
        {
            'id': 3,
            'lines': [
                'rax = mul (2) (rdi)',
            ],
        },
        {
            'id': 4,
            'lines': [
                'exit context?', \
                'rcx = rax',
            ],
        },
        {
            'id': 5,
            'lines': [
                'rax = rcx',
            ],
        }
    ],
    'edges': [
        {
            'from': 1,
            'to': 5,
            'type': 'true',
        },
        {
            'from': 1,
            'to': 2,
            'type': 'false',
        },
        {
            'from': 2,
            'to': 3,
            'type': 'call',
        },
        {
            'from': 3,
            'to': 4,
            'type': 'return',
        },
        {
            'from': 4,
            'to': 5,
            'type': 'unconditional',
        }
    ]
}

EDGE_TYPES = {
    'true': (BranchType.TrueBranch, None),
    'false': (BranchType.FalseBranch, None),
    'unconditional': (BranchType.UnconditionalBranch, None),
    'call': (BranchType.UserDefinedBranch,
             EdgeStyle(style=EdgePenStyle.DashLine,
                       theme_color=ThemeColor.UnconditionalBranchColor)),
    'return': (BranchType.UserDefinedBranch,
               EdgeStyle(style=EdgePenStyle.DotLine,
                         theme_color=ThemeColor.UnconditionalBranchColor)),
}


def show_cfg(cfg: Dict[str, Any] = example_graph):
    graph = FlowGraph()
    nodes = {}

    for node in cfg['nodes']:
        fg_node = FlowGraphNode(graph)
        fg_node.lines = node['lines']
        nodes[node['id']] = fg_node
        graph.append(fg_node)

    for edge in cfg['edges']:
        branch_type, edge_style = EDGE_TYPES[edge['type']]
        nodes[edge['from']].add_outgoing_edge(branch_type, nodes[edge['to']],
                                              edge_style)
    show_graph_report("Graph", graph)

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
