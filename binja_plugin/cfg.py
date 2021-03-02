from typing import Dict, Any, Tuple, Optional
from pathlib import Path
import json

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

ENTER_FUNC_TAG = 'EnterFunc'
LEAVE_FUNC_TAG = 'LeaveFunc'
BASIC_BLOCK_TAG = 'BasicBlock'


def fixup_graph(graph):
    graph = {**graph, 'nodeMap': {k: v for [k, v] in graph['nodeMap']}}
    return graph


with open(Path(__file__).parent / 'res' / 'cfg.json') as f:
    BEFORE_GRAPH = fixup_graph(json.load(f))

with open(Path(__file__).parent / 'res' / 'cfg_pruned.json') as f:
    AFTER_GRAPH = fixup_graph(json.load(f))


def get_edge_type(edge, nodes) -> Tuple[BranchType, Optional[EdgeStyle]]:
    node_from = nodes[edge['src']]
    node_to = nodes[edge['dst']]

    if node_to['tag'] == ENTER_FUNC_TAG:
        assert edge['branchType'] == 'UnconditionalBranch', 'bad assumption'
        return (BranchType.UserDefinedBranch,
                EdgeStyle(style=EdgePenStyle.DashLine,
                          theme_color=ThemeColor.UnconditionalBranchColor))

    if node_from['tag'] == LEAVE_FUNC_TAG:
        assert edge['branchType'] == 'UnconditionalBranch', 'bad assumption'
        return (BranchType.UserDefinedBranch,
                EdgeStyle(style=EdgePenStyle.DotLine,
                          theme_color=ThemeColor.UnconditionalBranchColor))

    return {
        'TrueBranch': (BranchType.TrueBranch, None),
        'FalseBranch': (BranchType.FalseBranch, None),
        'UnconditionalBranch': (BranchType.UnconditionalBranch, None),
    }[edge['branchType']]


def format_block_header(node_id: int, node: dict) -> str:
    tag = node['tag']
    start_addr = node["contents"].get("start", None)
    if tag == BASIC_BLOCK_TAG and start_addr is not None:
        return f'#{node_id} ({start_addr:#x}) {node["tag"]}'


def show_cfg(cfg: Dict[str, Any] = BEFORE_GRAPH):
    graph = FlowGraph()
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
        nodes[edge['src']].add_outgoing_edge(branch_type, nodes[edge['dst']],
                                             edge_style)
    show_graph_report("Graph", graph)
