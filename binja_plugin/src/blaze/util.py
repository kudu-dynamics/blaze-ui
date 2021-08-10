import copy
import dataclasses
import logging as _logging
from os import PathLike
from typing import Callable, List, Optional, Union

import binaryninja
from binaryninja import BinaryView
from binaryninja.enums import EdgePenStyle, ThemeColor
from binaryninja.flowgraph import EdgeStyle, FlowGraphEdge, FlowGraphNode
from binaryninjaui import ActionPriority, Menu, UIAction, UIActionContext, UIActionHandler

from .types import MenuOrder

log = _logging.getLogger(__name__)


@dataclasses.dataclass
class BNAction:
    group: str
    name: str
    menu_order: MenuOrder
    activate: Callable[[UIActionContext], None]
    isValid: Optional[Callable[[UIActionContext], bool]] = None
    submenu: Optional[str] = None
    priority: Optional[ActionPriority] = None


def bind_actions(action_handler: UIActionHandler, actions: List[BNAction]) -> None:
    for action in actions:
        ui_action = UIAction(action.activate, action.isValid or (lambda c: True))
        if action.priority is not None:
            action_handler.bindAction(action.name, ui_action, action.priority)
        else:
            action_handler.bindAction(action.name, ui_action)


def add_actions(context_menu: Menu, actions: List[BNAction]) -> None:
    for action in actions:
        if action.submenu is not None:
            context_menu.addAction(
                action.submenu, action.name, action.group, action.menu_order.to_int())
        else:
            context_menu.addAction(action.name, action.group, action.menu_order.to_int())


def fix_flowgraph_edge(edge: FlowGraphEdge, swapped: bool) -> FlowGraphEdge:
    source: FlowGraphNode
    target: FlowGraphNode

    if swapped:
        source, target = edge.target, edge.source
    else:
        source, target = edge.source, edge.target

    del edge

    # XXX due to a bug in binaryninjaui, we can't trust all the fields of
    # `getEdgeForMouseEvent(e)[0]`, so find the original edge and return that instead
    new_edge: FlowGraphEdge
    for new_edge in source.outgoing_edges:
        if new_edge.target == target:

            # XXX a similar bug requires this fixup: edge.style.style is
            # assigned the binaryninjacore `BNEdgeStyle` struct, so we need to
            # translate it to the python API types. This bug might get fixed in
            # the near future, in which case this will hopefully be dead code
            if isinstance(new_edge.style.style, binaryninja.core.BNEdgeStyle):
                core_style = new_edge.style.style
                new_edge = copy.copy(new_edge)
                new_edge.style = EdgeStyle(
                    style=EdgePenStyle(core_style.style),
                    width=core_style.width,
                    theme_color=ThemeColor(core_style.color),
                )

            return new_edge

    raise RuntimeError('Couldn\'t find `edge` among `edge.source.outgoing_edges`')


def try_log(log: _logging.Logger, level: int, error_level: int, msg: str, *args, **kwargs) -> None:
    '''
    Attempt to log `msg` with arguments `args` to log `log` at level `level`.
    If there are any exceptions, log the traceback to the same log but at level
    `error_level`. Note that ``msg % args`` is evaluated eagerly (though exceptions
    will be caught), even if the message would be ignored by the logger or its
    handlers
    '''

    try:
        if args:
            msg = msg % args
    except Exception:
        try:
            log.log(error_level, 'error formatting log message', exc_info=True)
        except Exception:
            pass
    else:
        try:
            log.log(level, msg, **kwargs)
        except Exception:
            try:
                log.log(error_level, 'error logging', exc_info=True)
            except Exception:
                pass


def try_debug(log: _logging.Logger, msg: str, *args, **kwargs) -> None:
    '''
    Like `try_log`, but fix both levels to `logging.DEBUG`
    '''

    try_log(log, _logging.DEBUG, _logging.DEBUG, msg, *args, **kwargs)


def bv_key(bv_or_path: Union[BinaryView, str, PathLike]) -> str:
    path = bv_or_path.file.filename if isinstance(bv_or_path, BinaryView) else str(bv_or_path)
    return path if path.endswith('.bndb') else path + '.bndb'
