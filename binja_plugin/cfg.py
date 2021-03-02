from typing import Dict, Any, Tuple, Optional
from pathlib import Path
import json
import enum

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


class CFNode(str, enum.Enum):
    BasicBlock = 'BasicBlock'
    Call = 'Call'
    EnterFunc = 'EnterFunc'
    LeaveFunc = 'LeaveFunc'


def fixup_graph(graph):
    graph = {**graph, 'nodeMap': {k: v for [k, v] in graph['nodeMap']}}
    return graph


with open(Path(__file__).parent / 'res' / 'cfg.json') as f:
    BEFORE_GRAPH = fixup_graph(json.load(f))

with open(Path(__file__).parent / 'res' / 'cfg_pruned.json') as f:
    AFTER_GRAPH = fixup_graph(json.load(f))

BEFORE_GRAPH_HIGHLIGHTING = {
    53: HighlightStandardColor.RedHighlightColor,
    59: HighlightStandardColor.YellowHighlightColor,
    66: HighlightStandardColor.GreenHighlightColor,
    82: HighlightStandardColor.BlueHighlightColor
}

AFTER_GRAPH_HIGHLIGHTING = {
    46: HighlightStandardColor.RedHighlightColor,
    52: HighlightStandardColor.YellowHighlightColor,
    53: HighlightStandardColor.GreenHighlightColor,
    56: HighlightStandardColor.BlueHighlightColor
}


def get_edge_type(edge, nodes) -> Tuple[BranchType, Optional[EdgeStyle]]:
    node_from = nodes[edge['src']]
    node_to = nodes[edge['dst']]

    if node_to['tag'] == CFNode.EnterFunc:
        assert edge['branchType'] == 'UnconditionalBranch', 'bad assumption'
        return (BranchType.UserDefinedBranch,
                EdgeStyle(style=EdgePenStyle.DashLine,
                          theme_color=ThemeColor.UnconditionalBranchColor))

    if node_from['tag'] == CFNode.LeaveFunc:
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


def show_cfg(
        cfg: Dict[str, Any] = BEFORE_GRAPH,
        highlighting: Optional[Dict[int, HighlightStandardColor]] = None) \
        -> None:

    highlighting = highlighting if highlighting else {}

    graph = FlowGraph()
    nodes = {}

    for (node_id, node) in cfg['nodeMap'].items():
        fg_node = FlowGraphNode(graph)

        if (highlight := highlighting.get(node_id)) is not None:
            fg_node.highlight = highlight

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


PluginCommand.register_for_function(
    r'Blaze\PIL ICFG', 'Display PIL interprocedural CFG',
    lambda bv, func: show_cfg(BEFORE_GRAPH, BEFORE_GRAPH_HIGHLIGHTING))

PluginCommand.register_for_function(
    r'Blaze\PIL ICFG (pruned)', 'Display pruned PIL interprocedural CFG',
    lambda bv, func: show_cfg(AFTER_GRAPH, AFTER_GRAPH_HIGHLIGHTING))
