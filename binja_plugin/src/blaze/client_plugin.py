import asyncio
import enum
import json
import logging as _logging
import os
import os.path
import queue
import requests
import tempfile
import threading
from typing import Dict, Literal, Optional, Union, cast, Callable
import uuid

import websockets
from binaryninja import BinaryView, PluginCommand, user_plugin_path
from binaryninjaui import DockHandler, ViewFrame
from binaryninja.interaction import show_message_box, MessageBoxButtonSet, MessageBoxIcon, MessageBoxButtonResult
from PySide2.QtCore import Qt
from PySide2.QtWidgets import QApplication, QWidget
from websockets.client import WebSocketClientProtocol

from .cfg import ICFGDockWidget, ICFGFlowGraph, cfg_from_server
from .types import BinjaMessage, BinjaToServer, CfgId, ServerCfg, ServerToBinja, BlazeConfig, ClientId, BinaryHash

LOG_LEVEL = 'INFO'
BLAZE_UI_HOST = os.environ.get('BLAZE_UI_HOST', 'localhost')
BLAZE_UI_WS_PORT = os.environ.get('BLAZE_UI_WS_PORT', '31337')
BLAZE_UI_HTTP_PORT = os.environ.get('BLAZE_UI_HTTP_PORT', '31338')
BLAZE_WS_SHUTDOWN = 'SHUTDOWN'

log = _logging.getLogger(__name__)


def register_for_function(action, description):
    def wrapper(f):
        PluginCommand.register_for_function(action, description, f)
        return f

    return wrapper

def get_blaze_config() -> BlazeConfig:
    "Gets config from .blaze, or creates it"
    blaze_file = user_plugin_path() + "/.blaze"
    try:
        f = open(blaze_file, "r")
        data = f.read()
        cfg = json.loads(data)
        return cfg
    except IOError:
        f = open(blaze_file, "w")
        cfg = {'client_id': str(uuid.uuid4())}
        data = json.dumps(cfg)
        f.write(data)
        log.info("Created .blaze config file")
        f.close()
    finally:
        f.close()

def register(action, description):
    def wrapper(f):
        PluginCommand.register(action, description, f)
        return f

    return wrapper

    

class BlazeInstance():
    def __init__(self, bv: BinaryView, blaze: 'BlazePlugin'):
        self.bv: BinaryView = bv
        self.blaze: 'BlazePlugin' = blaze
        self.graph: Optional[ICFGFlowGraph] = None
        self.bndbHash: Optional[BinaryHash] = None

    def send(self, msg: BinjaToServer):
        self.blaze.send(self.bv, msg)

    def with_bndb_hash(self, callback: Callable[[BinaryHash], None]) -> None:
        def set_hash_and_do_callback (h: BinaryHash) -> None:
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
        
        self.dock_handler: DockHandler
        if hasattr(DockHandler, 'getActiveDockHandler'):
            self.dock_handler = DockHandler.getActiveDockHandler()
        else:
            main_window = QApplication.allWidgets()[0].window()
            self.dock_handler = main_window.findChild(DockHandler, '__DockHandler')
        assert self.dock_handler

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
            False
        )

        self.config = get_blaze_config()
        self.client_id = self.config['client_id']

    def _init_thread(self) -> None:
        if not self.websocket_thread or not self.websocket_thread.is_alive():
            log.info('Starting or restarting websocket thread')
            self.out_queue = queue.Queue()
            t = threading.Thread(target=lambda: asyncio.run(self.main_websocket_loop()))
            t.name = 'Blaze websocket thread'
            t.start()
            self.websocket_thread = t

    def shutdown(self) -> None:
        if self.websocket_thread and self.websocket_thread.is_alive():
            log.info('Shutting down')
            try:
                self.out_queue.put(BLAZE_WS_SHUTDOWN, timeout=1)
            except queue.Full:
                log.warn('websocket queue is full, cannot shutdown')
                return

            self.websocket_thread.join(timeout=1)
            if self.websocket_thread.is_alive():
                log.warn('websocket thread is still alive after timeout')

    def upload_bndb(self, bv: BinaryView, callback: Callable[[BinaryHash], None]) -> None:
        if (not bv.file.filename.endswith('.bndb')):
            bndb_filename = bv.file.filename + '.bndb'
            if (os.path.isfile(bndb_filename)):
                msg = "Is it ok to overwrite existing analysis database " + bndb_filename + " ? If not, please manually load bndb and try again."
            else:
                msg = "Is it ok to save analysis database to " + bndb_filename + " ?"
            to_save: Optional[MessageBoxButtonResult] = show_message_box(
                "Blaze",
                msg,
                buttons=MessageBoxButtonSet.YesNoButtonSet,
                icon=MessageBoxIcon.WarningIcon
            )

            if to_save == MessageBoxButtonResult.NoButton:
                log.error("failed to send analysis database because it is not yet saved")
                return
            else:
                bv.create_database(bndb_filename)
                
        # by now, bv is saved as bndb and bv.file.filename is bndb
        og_filename = bv.file.filename

        if bv.file.analysis_changed:
            bv.create_database(og_filename)
        
        # tf = tempfile.NamedTemporaryFile()
        # temp_bndb_name = tf.name + '.bndb'
        # tf.close()
        # bv.create_database(temp_bndb_name)
        uri = "http://" + BLAZE_UI_HOST + ":" + BLAZE_UI_HTTP_PORT + "/upload"
        # handle = open(temp_bndb_name,'rb')
        handle = open(og_filename, 'rb')
        files = { 'bndb': handle }
        post_data = {'hostBinaryPath': og_filename,
                     'clientId': self.client_id,
                    }
        # TODO: run this in thread with callback
        r = requests.post(uri, data=post_data, files=files)
        handle.close()
        rj = r.json()
        log.info(str(rj))

        # os.remove(temp_bndb_name)
        # bv.create_database(og_filename)
        callback(rj)
        
                
    def ensure_instance(self, bv: BinaryView) -> BlazeInstance:
        if (instance := BlazePlugin.instances.get(bv.file.filename)) is not None:
            return instance

        instance = BlazeInstance(bv, self)
        BlazePlugin.instances[bv.file.filename] = instance
        return instance

    def send(self, bv: BinaryView, msg: BinjaToServer) -> None:
        self._init_thread()
        self.ensure_instance(bv)

        new_msg = BinjaMessage(clientId=self.client_id, hostBinaryPath=bv.file.filename, action=msg)
            # log.debug('enqueueing %s', new_msg)
        self.out_queue.put(new_msg)


    async def main_websocket_loop(self):
        uri = "ws://" + BLAZE_UI_HOST + ":" + BLAZE_UI_WS_PORT + "/binja"

        log.info('connecting to websocket...')
        async with websockets.connect(uri) as websocket:
            log.info('connected')
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
            try:
                msg = json.loads(ws_msg)
            except json.JSONDecodeError:
                log.exception('malformed message')
                continue

            instance: Optional[BlazeInstance] = self.instances.get(msg['hostBinaryPath'])
            if instance is None:
                log.error("couldn't find blaze instance in mapping for %s", msg)
                continue

            # log.debug('Blaze: received %r', msg)
            try:
                self.message_handler(instance, msg['action'])
            except Exception:
                log.exception("couldn't handle message")
                continue

    async def send_loop(self, websocket) -> None:
        while True:
            msg = await asyncio.get_running_loop().run_in_executor(None, self.out_queue.get)
            if msg == BLAZE_WS_SHUTDOWN:
                self.out_queue.task_done()
                return

            json_msg = json.dumps(msg)
            # log.debug('sending %r', json_msg)

            try:
                await websocket.send(json_msg)
            except:
                return
            log.debug('sent')
            self.out_queue.task_done()

    def message_handler(self, instance: BlazeInstance, msg: ServerToBinja) -> None:
        tag = msg['tag']
        # log.debug('Got message: %s', json.dumps(msg, indent=2))

        if tag == 'SBLogInfo':
            log.info(msg['message'])

        elif tag == 'SBLogWarn':
            log.warn(msg['message'])

        elif tag == 'SBLogError':
            log.error(msg['message'])

        elif tag == 'SBNoop':
            log.info("got Noop")

        elif tag == 'SBCfg':
            cfg_id = cast(CfgId, msg['cfgId'])
            bndb_hash = cast(BinaryHash, msg['bndbHash'])
            cfg = cast(ServerCfg, msg['cfg'])
            self.icfg_dock_widget.icfg_widget.set_icfg(cfg_id, cfg_from_server(cfg))

        else:
            log.error("Blaze: unknown message type: %s", tag)


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
    blaze_instance.with_bndb_hash(lambda h: blaze_instance.send(BinjaToServer(tag='BSCfgNew', startFuncAddress=func.start, bndbHash=h)))


def listen_start(bv):
    pass


def listen_stop(bv):
    pass


# PluginCommand.register_for_medium_level_il_instruction(actionSendInstruction, "Send Instruction", send_instruction)

# UIAction.registerAction(actionSayHello, "CTRL+1")
# UIAction.registerAction(sendEndAction, "CTRL+2")
# UIAction.registerAction(findPathAction, "CTRL+3")
