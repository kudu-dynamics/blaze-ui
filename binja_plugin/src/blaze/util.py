import copy
from binaryninja import BinaryView
import dataclasses
import logging as _logging
from os import PathLike
from typing import Callable, List, Optional, Union
from binaryninja.flowgraph import FlowGraphEdge

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
            context_menu.addAction(action.submenu, action.name, action.group,
                                   action.menu_order.to_int())
        else:
            context_menu.addAction(action.name, action.group, action.menu_order.to_int())


def fix_flowgraph_edge(edge: FlowGraphEdge, swapped: bool) -> FlowGraphEdge:
    if swapped:
        edge = copy.copy(edge)
        edge.source, edge.target = edge.target, edge.source

    return edge


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


ITEM_DATE_FMT_IN = 'YYYY-DD-SSTHH:MM:SS'
ITEM_DATE_FMT_OUT = '%b %d, %Y @ %H:%M:%S'


def servertime_to_clienttime(timestamp) -> str:
    """
    Timestamps coming in from the server have 7-digit floats instead of 6
    We need to remove those... Regex is best, but for now we're just getting Zulu time
    """
    if timestamp.endswith('Z'):
        return timestamp[:len(ITEM_DATE_FMT_IN)]
    else:
        # TODO non-Zulu time
        return timestamp[:len(ITEM_DATE_FMT_IN)]