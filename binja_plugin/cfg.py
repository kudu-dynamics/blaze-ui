import enum
from typing import Any, Dict, Optional, Tuple

from binaryninja import BinaryView
from binaryninja.enums import BranchType, EdgePenStyle, ThemeColor
from binaryninja.flowgraph import EdgeStyle, FlowGraph, FlowGraphNode
from binaryninja.interaction import show_graph_report

import logging
log = logging.getLogger(__name__)
del logging

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
    return None


def display_icfg(_bv: BinaryView, cfg: Dict[str, Any]) -> None:
    cfg = {**cfg, 'nodeMap': {k: v for [k, v] in cfg['nodeMap']}}

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
        nodes[edge['src']].add_outgoing_edge(branch_type, nodes[edge['dst']], edge_style)
    show_graph_report("PIL ICFG", graph)
