import asyncio
import enum
import json
import logging as _logging
import os
import os.path
import queue
import threading
from typing import Callable, Dict, Literal, Optional, Union, cast

import binaryninjaui
import requests
import websockets
from binaryninja import BinaryView, PluginCommand
from binaryninja.interaction import (
    MessageBoxButtonResult,
    MessageBoxButtonSet,
    MessageBoxIcon,
    show_message_box,
)
from binaryninjaui import DockHandler, ViewFrame
from websockets.client import WebSocketClientProtocol

REQUEST_ACTIVITY_TIMEOUT = 5

if getattr(binaryninjaui, 'qt_major_version', None) == 6:
    from PySide6.QtCore import Qt  # type: ignore
    from PySide6.QtWidgets import QApplication, QWidget  # type: ignore
else:
    from PySide2.QtCore import Qt  # type: ignore
    from PySide2.QtWidgets import QApplication, QWidget  # type: ignore

from .cfg import ICFGDockWidget, ICFGFlowGraph, cfg_from_server
from .settings import BlazeSettings
from .snaptree import SnapTreeDockWidget
from .types import (
    BinaryHash,
    BinjaMessage,
    BinjaToServer,
    CfgId,
    ServerCfg,
    ServerToBinja,
    SnapshotBinjaToServer,
    SnapshotServerToBinja,
)
from .util import try_debug

BLAZE_WS_SHUTDOWN = 'SHUTDOWN'

log = _logging.getLogger(__name__)


def register_for_function(action, description):
    def wrapper(f):
        log.debug('Registering handler %r for action %r description %r', f, action, description)
        PluginCommand.register_for_function(action, description, f)
        return f

    return wrapper


def register(action, description):
    def wrapper(f):
        log.debug('Registering handler %r for action %r description %r', f, action, description)
        PluginCommand.register(action, description, f)
        return f

    return wrapper


def bv_key(bv: BinaryView) -> str:
    return bv.file.filename if bv.file.filename.endswith('.bndb') else bv.file.filename + '.bndb'


class BlazeInstance():
    def __init__(self, bv: BinaryView, blaze: 'BlazePlugin'):
        self.bv: BinaryView = bv
        self.blaze: 'BlazePlugin' = blaze
        self.graph: Optional[ICFGFlowGraph] = None
        self.bndbHash: Optional[BinaryHash] = None

        log.debug('%r initialized', self)

    def __del__(self):
        try_debug(log, 'Deleting %r', self)

    def send(self, msg: BinjaToServer):
        self.blaze.send(self.bv, msg)

    def get_bv_key(self) -> str:
        return bv_key(self.bv)

    def with_bndb_hash(self, callback: Callable[[BinaryHash], None]) -> None:
        def set_hash_and_do_callback(h: BinaryHash) -> None:
            self.bndbHash = h
            callback(h)

        if self.bndbHash == None or self.bv.file.analysis_changed or self.bv.file.modified:
            blaze.upload_bndb(self.bv, set_hash_and_do_callback)
        else:
            callback(self.bndbHash)


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

        self.icfg_dock_widget: ICFGDockWidget

        def create_icfg_widget(name: str, parent: ViewFrame, bv: BinaryView) -> QWidget:
            dock_handler = DockHandler.getActiveDockHandler()
            self.icfg_dock_widget = ICFGDockWidget(
                name=name,
                view_frame=dock_handler.getViewFrame(),
                parent=parent,
                blaze_instance=self.ensure_instance(bv))
            return self.icfg_dock_widget

        self.dock_handler.addDockWidget( \
            "Blaze ICFG",
            create_icfg_widget,
            Qt.DockWidgetArea.RightDockWidgetArea,
            Qt.Orientation.Vertical,
            False  # default visibility
        )

        log.debug('Created ICFG dock widget')

        # -- Add SnapTree View

        self.snaptree_dock_widget: SnapTreeDockWidget

        def create_snaptree_widget(name: str, parent: ViewFrame, bv: BinaryView) -> QWidget:
            dock_handler = DockHandler.getActiveDockHandler()
            self.snaptree_dock_widget = SnapTreeDockWidget(
                name=name,
                view_frame=dock_handler.getViewFrame(),
                parent=parent,
                blaze_instance=self.ensure_instance(bv))
            return self.snaptree_dock_widget

        self.dock_handler.addDockWidget(
            "Blaze Snapshot Tree",
            create_snaptree_widget,
            Qt.DockWidgetArea.LeftDockWidgetArea,
            Qt.Orientation.Vertical,
            False  # default visibility
        )

        log.debug('Created snaptree dock widget')

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
        if (not bv.file.filename.endswith('.bndb')):
            bndb_filename = bv.file.filename + '.bndb'
            if (os.path.isfile(bndb_filename)):
                msg = f"Is it ok to overwrite existing analysis database {bndb_filename}? If not, please manually load bndb and try again."
            else:
                msg = f"Is it ok to save analysis database to {bndb_filename}?"
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

        # TODO: run the following in a thread
        uri = f'http://{self.settings.host}:{self.settings.http_port}/upload'
        with open(og_filename, 'rb') as f:
            files = {'bndb': f}
            post_data = {
                'hostBinaryPath': og_filename,
                'clientId': self.settings.client_id,
            }
            r = requests.post(uri, data=post_data, files=files, timeout=REQUEST_ACTIVITY_TIMEOUT)

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

        log.debug('Creating new blaze instance for BV: %r', bv)
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
            bndb_hash = cast(BinaryHash, msg.get('bndbHash'))
            cfg = cast(ServerCfg, msg.get('cfg'))
            self.icfg_dock_widget.icfg_widget.set_icfg(cfg_id, cfg_from_server(cfg))
            self.snaptree_dock_widget.snaptree_widget.focus_icfg(cfg_id)

        elif tag == 'SBSnapshot':
            snap_msg = cast(SnapshotServerToBinja, msg.get('snapshotMsg'))
            self.snaptree_dock_widget.handle_server_msg(snap_msg)

        else:
            log.error("Unknown message type: %r", tag)


try:
    blaze  # type: ignore
except NameError:
    pass
else:
    blaze.shutdown()  # type: ignore

blaze = BlazePlugin()


class Action(str, enum.Enum):
    SAY_HELLO = r'Blaze\Say Hello'
    SEND_INSTRUCTION = r'Blaze\Send Instruction'
    TYPE_CHECK_FUNCTION = r'Blaze\Type Check Function'
    START_CFG = r'Blaze\Create ICFG'


@register_for_function(Action.START_CFG, 'Create ICFG')
def start_cfg(bv, func):
    blaze.icfg_dock_widget.icfg_widget.recenter_node_id = None
    blaze_instance = blaze.ensure_instance(bv)
    blaze_instance.with_bndb_hash(
        lambda h: blaze_instance.send(
            BinjaToServer(tag='BSCfgNew', startFuncAddress=func.start, bndbHash=h)))


def listen_start(bv):
    pass


def listen_stop(bv):
    pass


# PluginCommand.register_for_medium_level_il_instruction(actionSendInstruction, "Send Instruction", send_instruction)

# UIAction.registerAction(actionSayHello, "CTRL+1")
# UIAction.registerAction(sendEndAction, "CTRL+2")
# UIAction.registerAction(findPathAction, "CTRL+3")
