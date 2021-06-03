import logging as _logging
from copy import deepcopy
from typing import TYPE_CHECKING, Dict, List, Optional, Tuple, Union, cast

from binaryninja import BinaryView
from binaryninja.enums import BranchType, EdgePenStyle, HighlightStandardColor, ThemeColor
from binaryninja.flowgraph import EdgeStyle, FlowGraph, FlowGraphEdge, FlowGraphNode
from binaryninja.interaction import (
    MessageBoxButtonResult,
    MessageBoxButtonSet,
    MessageBoxIcon,
    show_message_box,
)
from binaryninjaui import (
    ContextMenuManager,
    DockContextHandler,
    FlowGraphWidget,
    Menu,
    UIActionContext,
    UIActionHandler,
    ViewFrame,
)
from PySide2.QtCore import QEvent, QObject, Qt
from PySide2.QtGui import QContextMenuEvent, QMouseEvent
from PySide2.QtWidgets import QVBoxLayout, QWidget

from .types import (
    BINARYNINJAUI_CUSTOM_EVENT,
    UUID,
    BinjaToServer,
    CfgId,
    MenuOrder,
    ServerCfg,
    SnapshotServerToBinja,
)
from .util import BNAction, add_actions, bind_actions, fix_flowgraph_edge

if TYPE_CHECKING:
    from .client_plugin import BlazeInstance

VERBOSE = False

log = _logging.getLogger(__name__)


def snapshot_message_handler(msg: SnapshotServerToBinja) -> None:
    log.info(msg)
