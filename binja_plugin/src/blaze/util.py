import copy
import dataclasses
import logging as _logging
from pathlib import Path
from typing import Any, Callable, Iterable, List, Optional, TypeVar, Union, cast

import binaryninja
from binaryninja import BinaryView
from binaryninja.binaryview import Section
from binaryninja.enums import EdgePenStyle, ThemeColor
from binaryninja.flowgraph import EdgeStyle, FlowGraphEdge, FlowGraphNode
from binaryninja.plugin import PluginCommand
from binaryninjaui import ActionPriority, Menu, UIAction, UIActionContext, UIActionHandler

from .types import MenuOrder

log = _logging.getLogger(__name__)

T = TypeVar('T')
_Decorator = Callable[[T], T]
_FunctionAction = Callable[[BinaryView, binaryninja.Function], None]
_AddressAction = Callable[[BinaryView, int], None]
_ViewAction = Callable[[BinaryView], None]


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
        UIAction.registerAction(action.name)
        ui_action = UIAction(action.activate, action.isValid or (lambda _: True))
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
    if swapped:
        source: FlowGraphNode = edge.target
        target: FlowGraphNode = edge.source
    else:
        source: FlowGraphNode = edge.source
        target: FlowGraphNode = edge.target

    del edge

    # XXX due to a bug in binaryninjaui, we can't trust all the fields of
    # `getEdgeForMouseEvent(e)[0]`, so find the original edge and return that instead
    for new_edge in cast(Iterable[FlowGraphEdge], source.outgoing_edges):
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


def try_log(
        log: _logging.Logger, level: int, error_level: int, msg: str, *args: Any,
        **kwargs: Any) -> None:
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


def try_debug(log: _logging.Logger, msg: str, *args: Any, **kwargs: Any) -> None:
    '''
    Like `try_log`, but fix both levels to `logging.DEBUG`
    '''

    try_log(log, _logging.DEBUG, _logging.DEBUG, msg, *args, **kwargs)


def bv_key(bv_or_path: Union[BinaryView, str, Path]) -> str:
    path: str = bv_or_path.file.filename if isinstance(bv_or_path, BinaryView) else str(bv_or_path)
    return path if path.endswith('.bndb') else path + '.bndb'


ITEM_DATE_FMT_IN = 'YYYY-DD-SSTHH:MM:SS'
ITEM_DATE_FMT_OUT = '%b %d, %Y @ %H:%M:%S'


def servertime_to_clienttime(timestamp: str) -> str:
    """
    Timestamps coming in from the server have 7-digit floats instead of 6
    We need to remove those... Regex is best, but for now we're just getting Zulu time
    """
    if timestamp.endswith('Z'):
        return timestamp[:len(ITEM_DATE_FMT_IN)]
    else:
        # TODO non-Zulu time
        return timestamp[:len(ITEM_DATE_FMT_IN)]


def get_sections_at(bv: BinaryView, addr: int) -> List[Section]:
    return bv.get_sections_at(addr)


def get_functions_containing(bv: BinaryView, addr: int) -> List[binaryninja.Function]:
    return bv.get_functions_containing(addr)


def get_function_at(bv: BinaryView, addr: int) -> Optional[binaryninja.Function]:
    return cast(Optional[binaryninja.Function], bv.get_function_at(addr))


def register_for_function(action: str, description: str) -> _Decorator[_FunctionAction]:
    def wrapper(f: _FunctionAction) -> _FunctionAction:
        log.debug('Registering handler %r for action %r description %r', f, action, description)
        PluginCommand.register_for_function(action, description, f)
        return f

    return wrapper


def register_for_address(action: str, description: str) -> _Decorator[_AddressAction]:
    def wrapper(f: _AddressAction) -> _AddressAction:
        log.debug('Registering handler %r for action %r description %r', f, action, description)
        PluginCommand.register_for_address(action, description, f)
        return f

    return wrapper


def register(action: str, description: str) -> _Decorator[_ViewAction]:
    def wrapper(f: _ViewAction) -> _ViewAction:
        log.debug('Registering handler %r for action %r description %r', f, action, description)
        PluginCommand.register(action, description, f)
        return f

    return wrapper
