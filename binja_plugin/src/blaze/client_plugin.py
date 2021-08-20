import asyncio
from datetime import datetime
import enum
import json
import logging as _logging
import os
import os.path
import queue
import threading
from typing import Callable, DefaultDict, Dict, List, Literal, Optional, Union, cast

import binaryninjaui
import requests
import websockets
from binaryninja import BinaryView, PluginCommand, BackgroundTaskThread
from binaryninja.interaction import (
    MessageBoxButtonResult,
    MessageBoxButtonSet,
    MessageBoxIcon,
    show_message_box,
)
from binaryninjaui import DockHandler, FileContext, UIContext, UIContextNotification, ViewFrame
from websockets.client import WebSocketClientProtocol

REQUEST_ACTIVITY_TIMEOUT = 5

if getattr(binaryninjaui, 'qt_major_version', None) == 6:
    from PySide6.QtCore import Qt
    from PySide6.QtWidgets import QApplication, QWidget  # type: ignore
else:
    from PySide2.QtCore import Qt  # type: ignore
    from PySide2.QtWidgets import QApplication, QWidget  # type: ignore

from .cfg import ICFGDockWidget, ICFGFlowGraph, cfg_from_server
from .poi import PoiListDockWidget, PoiListItem
from .settings import BlazeSettings
from .snaptree import SnapTreeDockWidget
from .types import (
    BinaryHash,
    BinjaMessage,
    BinjaToServer,
    CfgId,
    PendingChanges,
    HostBinaryPath,
    PoiBinjaToServer,
    PoiSearchResults,
    PoiServerToBinja,
    ServerCfg,
    ServerPendingChanges,
    ServerPoiSearchResults,
    ServerToBinja,
    SnapshotServerToBinja,
    pending_changes_from_server,
)
from .util import bv_key, try_debug

BLAZE_WS_SHUTDOWN = 'SHUTDOWN'

log = _logging.getLogger(__name__)


def register_for_function(action, description):
    def wrapper(f):
        log.debug('Registering handler %r for action %r description %r', f, action, description)
        PluginCommand.register_for_function(action, description, f)
        return f

    return wrapper


def register_for_address(action, description):
    def wrapper(f):
        log.debug('Registering handler %r for action %r description %r', f, action, description)
        PluginCommand.register_for_address(action, description, f)
        return f

    return wrapper


def register(action, description):
    def wrapper(f):
        log.debug('Registering handler %r for action %r description %r', f, action, description)
        PluginCommand.register(action, description, f)
        return f

    return wrapper


class BlazeInstance():
    def __init__(self, bv: BinaryView, blaze: 'BlazePlugin'):
        self.bv: BinaryView = bv
        self.blaze: 'BlazePlugin' = blaze
        self.graph: Optional[ICFGFlowGraph] = None
        self.bndbHash: Optional[BinaryHash] = None

        log.debug('%r initialized', self)

    def __repr__(self):
        return f'<BlazeInstance({self.bv!r}, {self.blaze!r}) at {hex(id(self))}>'

    def __del__(self):
        try_debug(log, 'Deleting %r', self)

    def send(self, msg: BinjaToServer):
        self.blaze.send(self.bv, msg)

    @property
    def bv_key(self) -> str:
        return bv_key(self.bv)

    def with_bndb_hash(self, callback: Callable[[BinaryHash], None]) -> None:
        def set_hash_and_do_callback(h: BinaryHash) -> None:
            self.bndbHash = h
            callback(h)

        if self.bndbHash == None or self.bv.file.analysis_changed or self.bv.file.modified:
            u = UploadBndb(
                f'Uploading {self.bv.file.filename!r} to Blaze server...', self.blaze, self.bv,
                set_hash_and_do_callback)
            u.start()
        else:
            callback(self.bndbHash)


class UploadBndb(BackgroundTaskThread):
    def __init__(
        self,
        msg: str,
        blaze: 'BlazePlugin',
        bv: BinaryView,
        callback: Callable[[BinaryHash], None],
    ) -> None:
        BackgroundTaskThread.__init__(self, msg, False)
        self.bv: BinaryView = bv
        self.blaze: 'BlazePlugin' = blaze
        self.callback: Callable[[BinaryHash], None] = callback

    def run(self):
        self.blaze.upload_bndb(self.bv, self.callback)


class BlazePlugin():
    instances: Dict[str, BlazeInstance] = {}
    out_queue: "queue.Queue[Union[Literal['SHUTDOWN'], BinjaMessage]]"

    def __init__(self) -> None:
        self.websocket_thread: Optional[threading.Thread] = None
        self.settings: BlazeSettings = BlazeSettings()

        self.dock_handler: DockHandler
        if hasattr(DockHandler, 'getActiveDockHandler'):
            self.dock_handler = DockHandler.getActiveDockHandler()
        else:
            main_window = QApplication.allWidgets()[0].window()
            self.dock_handler = main_window.findChild(DockHandler, '__DockHandler')
        assert self.dock_handler

        # -- Add ICFG View

        self.icfg_dock_widgets: Dict[str, List[ICFGDockWidget]] = DefaultDict(list)

        def create_icfg_widget(name: str, parent: ViewFrame, bv: BinaryView) -> QWidget:
            dock_handler = DockHandler.getActiveDockHandler()
            widget = ICFGDockWidget(
                name=name,
                view_frame=dock_handler.getViewFrame(),
                parent=parent,
                blaze_instance=self.ensure_instance(bv))
            self.icfg_dock_widgets[bv_key(bv)].append(widget)
            return widget

        self.dock_handler.addDockWidget(
            "Blaze ICFG",
            create_icfg_widget,
            Qt.DockWidgetArea.RightDockWidgetArea,
            Qt.Orientation.Vertical,
            True  # default visibility
        )

        log.debug('Created ICFG dock widget')

        # -- Add SnapTree View

        self.snaptree_dock_widgets: Dict[str, List[SnapTreeDockWidget]] = DefaultDict(list)

        def create_snaptree_widget(name: str, parent: ViewFrame, bv: BinaryView) -> QWidget:
            dock_handler = DockHandler.getActiveDockHandler()
            widget = SnapTreeDockWidget(
                name=name,
                view_frame=dock_handler.getViewFrame(),
                parent=parent,
                blaze_instance=self.ensure_instance(bv))
            self.snaptree_dock_widgets[bv_key(bv)].append(widget)
            return widget

        self.dock_handler.addDockWidget(
            "Blaze Snapshot Tree",
            create_snaptree_widget,
            Qt.DockWidgetArea.BottomDockWidgetArea,
            Qt.Orientation.Vertical,
            True  # default visibility
        )

        log.debug('Created snaptree dock widget')

        # -- Add POI List View

        self.poi_dock_widgets: Dict[str, List[PoiListDockWidget]] = DefaultDict(list)

        def create_poi_widget(name: str, parent: ViewFrame, bv: BinaryView) -> QWidget:
            dock_handler = DockHandler.getActiveDockHandler()
            widget = PoiListDockWidget(
                name=name,
                view_frame=dock_handler.getViewFrame(),
                parent=parent,
                blaze_instance=self.ensure_instance(bv))
            self.poi_dock_widgets[bv_key(bv)].append(widget)
            return widget

        self.dock_handler.addDockWidget(
            "Blaze POI List",
            create_poi_widget,
            Qt.DockWidgetArea.BottomDockWidgetArea,
            Qt.Orientation.Vertical,
            True  # default visibility
        )

        log.debug('Create POI list widget')

        log.debug('%r initialized', self)

    def __del__(self):
        try_debug(log, 'Deleting %r', self)

    def _init_thread(self) -> None:
        if not self.websocket_thread or not self.websocket_thread.is_alive():
            log.info('Starting or restarting websocket thread')
            self.out_queue = queue.Queue()
            t = threading.Thread(target=lambda: asyncio.run(self.main_websocket_loop()))
            t.name = 'Blaze websocket thread'
            t.start()
            self.websocket_thread = t
            log.info('Started websocket thread')

    def shutdown(self) -> None:
        if self.websocket_thread and self.websocket_thread.is_alive():
            log.info('Shutting down websocket thread')
            try:
                self.out_queue.put(BLAZE_WS_SHUTDOWN, timeout=1)
            except queue.Full:
                log.error('websocket queue is full, cannot shutdown')
                return

            self.websocket_thread.join(timeout=1)
            if self.websocket_thread.is_alive():
                log.warn('websocket thread is still alive after timeout')

    def upload_bndb(self, bv: BinaryView, callback: Callable[[BinaryHash], None]) -> None:
        log.debug(
            f'{bv=!r}, {bv.file=!r}, {bv.file.raw=!r}, {bv.file.raw and bv.file.raw.handle = !r}')
        if (not bv.file.filename.endswith('.bndb')):
            bndb_filename = bv.file.filename + '.bndb'
            if (os.path.isfile(bndb_filename)):
                msg = f"This action will overwrite the existing analysis database {bndb_filename}. If you prefer to use your existing BNDB, please open it and try again.\n\nContinue with ICFG creation?"
            else:
                msg = f"This action requires generation of an analysis database (BNDB).\n\nContinue with ICFG creation?"
            to_save: Optional[MessageBoxButtonResult] = show_message_box(
                "Blaze",
                msg,
                buttons=MessageBoxButtonSet.YesNoButtonSet,
                icon=MessageBoxIcon.WarningIcon)

            if to_save == MessageBoxButtonResult.NoButton:
                log.error("failed to send analysis database because it is not yet saved")
                return
            else:
                bv.create_database(bndb_filename)

        # by now, bv is saved as bndb and bv.file.filename is bndb
        og_filename = bv.file.filename

        if bv.file.analysis_changed:
            bv.create_database(og_filename)

        uri = f'http://{self.settings.host}:{self.settings.http_port}/upload'
        with open(og_filename, 'rb') as f:
            files = {'bndb': f}
            post_data = {
                'hostBinaryPath': og_filename,
                'clientId': self.settings.client_id,
            }
            try:
                r = requests.post(
                    uri, data=post_data, files=files, timeout=(REQUEST_ACTIVITY_TIMEOUT, None))
            except requests.exceptions.RequestException as e:
                log.error('Failed to upload BNDB: ' + str(e))
                return None

        if r.status_code != requests.codes['ok']:
            log.error(
                'Backend server returned error (HTTP status %s): %r',
                r.status_code,
                r.text,
                extra={'error_payload': r.text})
            return

        rj = r.json()

        callback(rj)

    def ensure_instance(self, bv: BinaryView) -> BlazeInstance:
        '''
        Get the `BlazeInstance` associated with `bv`, or create one if none exists.
        Additionally, two `bv`s will be associated with the same `BlazeInstance`
        if they have the same filename, or if one of their filenames is the same as
        the other, but with `'.bndb'` appended. This way, for example,
        ``'/home/test/bash'`` and ``'/home/test/bash.bndb'`` will associate with
        the same `BlazeInstance`

        :return: the `BlazeInstance` for this `bv`, or if none exists, the one
            that was created
        '''

        instance_key = bv_key(bv)

        if (instance := BlazePlugin.instances.get(instance_key)) is not None:
            return instance

        log.info('Creating new blaze instance for BV: %r', bv)
        instance = BlazeInstance(bv, self)
        BlazePlugin.instances[instance_key] = instance

        return instance

    def send(self, bv: BinaryView, msg: BinjaToServer) -> None:
        self._init_thread()
        self.ensure_instance(bv)

        new_msg = BinjaMessage(
            clientId=self.settings.client_id, hostBinaryPath=bv_key(bv), action=msg)
        # log.debug('enqueueing %s', new_msg)
        self.out_queue.put(new_msg)

    async def main_websocket_loop(self):
        uri = f'ws://{self.settings.host}:{self.settings.ws_port}/binja'

        log.info('connecting to websocket...')
        try:
            async with websockets.connect(uri, max_size=None) as websocket:  # type: ignore
                log.info('connected to websocket')
                consumer_task = asyncio.ensure_future(self.recv_loop(websocket))
                producer_task = asyncio.ensure_future(self.send_loop(websocket))
                _, pending = await asyncio.wait(
                    [consumer_task, producer_task],
                    return_when=asyncio.FIRST_COMPLETED,
                )
                for task in pending:
                    task.cancel()
                    try:
                        await task
                    except asyncio.CancelledError:
                        pass
        except Exception as e:
            log.error("Websocket error: " + str(e))
            return None

    async def recv_loop(self, websocket: WebSocketClientProtocol) -> None:
        async for ws_msg in websocket:
            log.debug('Received websocket message', extra={'websocket_message': ws_msg})

            try:
                msg = json.loads(ws_msg)
            except json.JSONDecodeError:
                log.exception(
                    'Backend returned malformed message', extra={'websocket_message': ws_msg})
                continue

            instance: Optional[BlazeInstance] = self.instances.get(msg['hostBinaryPath'])
            if instance is None:
                log.error(
                    "Couldn't find existing blaze instance for %r",
                    msg['hostBinaryPath'],
                    extra={'blaze_instances': list(self.instances)})
                continue

            # log.debug('Blaze: received %r', msg)
            try:
                self.message_handler(instance, msg['action'])
            except Exception:
                log.exception("Couldn't handle message", extra={'websocket_message': msg})
                continue

    async def send_loop(self, websocket) -> None:
        while True:
            msg = await asyncio.get_running_loop().run_in_executor(None, self.out_queue.get)
            if msg == BLAZE_WS_SHUTDOWN:
                self.out_queue.task_done()
                return

            try:
                json_msg = json.dumps(msg)
            except Exception:
                log.exception('Could not JSON encode message to send to backend: %r', msg)
                continue

            log.debug('Sending websocket message...', extra={'websocket_message': json_msg})

            try:
                await websocket.send(json_msg)
            except Exception:
                log.exception('Failed to send message to backend')
                return

            log.debug('Sent websocket message')
            self.out_queue.task_done()

    def message_handler(self, instance: BlazeInstance, msg: ServerToBinja) -> None:
        tag = msg['tag']
        # log.debug('Got message: %s', json.dumps(msg, indent=2))

        if tag == 'SBLogInfo':
            log.info(msg.get('message'))

        elif tag == 'SBLogWarn':
            log.warn(msg.get('message'))

        elif tag == 'SBLogError':
            log.error(msg.get('message'))

        elif tag == 'SBNoop':
            log.info("got Noop")

        elif tag == 'SBCfg':
            cfg_id = cast(CfgId, msg.get('cfgId'))
            cfg = cfg_from_server(cast(ServerCfg, msg.get('cfg')))
            server_pending_changes = msg.get('pendingChanges')
            server_poi_search_results = msg.get('poiSearchResults')

            if server_poi_search_results:
                poi_search_results = PoiSearchResults(callNodeRatings=dict(server_poi_search_results.get('callNodeRatings') or []), presentTargetNodes=set(server_poi_search_results.get('presentTargetNodes') or []))
            else:
                poi_search_results = None

            if server_pending_changes is None:
                server_pending_changes = ServerPendingChanges(removedNodes=[], removedEdges=[])

            pending_changes = pending_changes_from_server(server_pending_changes)

            instance.graph = ICFGFlowGraph(instance.bv, cfg, cfg_id, poi_search_results, pending_changes)

            for dw in self.icfg_dock_widgets[instance.bv_key]:
                dw.set_graph(instance.graph)
            for dw in self.snaptree_dock_widgets[instance.bv_key]:
                dw.snaptree_widget.focus_icfg(cfg_id)

        elif tag == 'SBSnapshot':
            snap_msg = cast(SnapshotServerToBinja, msg.get('snapshotMsg'))
            for dw in self.snaptree_dock_widgets[instance.bv_key]:
                dw.handle_server_msg(snap_msg)

        elif tag == 'SBPoi':
            poi_msg = cast(PoiServerToBinja, msg.get('poiMsg'))
            for dw in self.poi_dock_widgets[instance.bv_key]:
                dw.handle_server_msg(poi_msg)

        else:
            log.error("Unknown message type: %r", tag)


class BlazeNotificationListener(UIContextNotification):
    # NOTE: We have to keep a reference around to the
    # `BlazeNotificationListener` instance, otherwise it will get garbage
    # collected and allocated over, even though `registerNotification` will have
    # kept a pointer to it, resulting in a segfault (or at the very least,
    # totally incorrect behavior) when any relevant notification fires
    instance: 'BlazeNotificationListener'

    def __init__(self, blaze_plugin: BlazePlugin):
        super().__init__()
        self.blaze_plugin: BlazePlugin = blaze_plugin

    def OnAfterCloseFile(self, context: UIContext, file: FileContext, frame: ViewFrame) -> None:
        key = bv_key(file.getFilename())
        bv = frame.getCurrentViewInterface().getData()
        log.debug('BinaryView closed', extra={'bv': bv, 'bv_filename': file.getFilename()})

        # Delete all DockWidgets associated with the now-closed BinaryView
        for widget_map in [
                self.blaze_plugin.icfg_dock_widgets,
                self.blaze_plugin.snaptree_dock_widgets,
        ]:
            for dw in list(dws := widget_map[key]):
                if dw.blaze_instance.bv == bv:
                    dws.remove(dw)

            if not dws:
                del widget_map[key]


blaze = BlazePlugin()
BlazeNotificationListener.instance = BlazeNotificationListener(blaze)
UIContext.registerNotification(BlazeNotificationListener.instance)


class Action(str, enum.Enum):
    SAY_HELLO = r'Blaze\Say Hello'
    SEND_INSTRUCTION = r'Blaze\Send Instruction'
    TYPE_CHECK_FUNCTION = r'Blaze\Type Check Function'
    START_CFG = r'Blaze\Create ICFG'
    MARK_POI = r'Blaze\Mark POI'


@register_for_function(Action.START_CFG, 'Create ICFG')
def start_cfg(bv, func):
    for dw in blaze.icfg_dock_widgets[bv_key(bv)]:
        dw.icfg_widget.recenter_node_id = None

    blaze_instance = blaze.ensure_instance(bv)
    blaze_instance.with_bndb_hash(
        lambda h: blaze_instance.send(
            BinjaToServer(tag='BSCfgNew', startFuncAddress=func.start, bndbHash=h)))


@register_for_address(Action.MARK_POI, 'Mark POI')
def mark_poi(bv, addr): 
    poi_list = None
    if funcs := bv.get_functions_containing(addr):
        # TODO: Decide how to handle multiple functions containing addr
        func = funcs[0]
        poi_msg = PoiBinjaToServer(
            tag='AddPoi', funcAddr=func.start, instrAddr=addr, name=None, description=None)
        blaze_instance = blaze.ensure_instance(bv)
        blaze_instance.send(BinjaToServer(tag='BSPoi', poiMsg=poi_msg))
    else:
        log.warn(r'No function containing address: 0x%x', addr)


def listen_start(bv):
    pass


def listen_stop(bv):
    pass


# PluginCommand.register_for_medium_level_il_instruction(actionSendInstruction, "Send Instruction", send_instruction)

# UIAction.registerAction(actionSayHello, "CTRL+1")
# UIAction.registerAction(sendEndAction, "CTRL+2")
# UIAction.registerAction(findPathAction, "CTRL+3")
