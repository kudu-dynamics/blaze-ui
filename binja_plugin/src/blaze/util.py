import copy
import dataclasses
import logging as _logging
from typing import Callable, List, Optional
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
