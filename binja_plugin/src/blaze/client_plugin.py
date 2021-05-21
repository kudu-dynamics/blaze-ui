import asyncio
import enum
import json
import logging as _logging
import os
import os.path
import queue
import threading
from typing import Dict, Literal, Optional, Union, cast

import websockets
from binaryninja import BinaryView, PluginCommand
from binaryninjaui import DockHandler, ViewFrame
from PySide2.QtCore import Qt
from PySide2.QtWidgets import QApplication, QWidget
from websockets.client import WebSocketClientProtocol

from .cfg import ICFGDockWidget, ICFGFlowGraph, cfg_from_server
from .types import BinjaMessage, BinjaToServer, CfgId, ServerCfg, ServerToBinja

LOG_LEVEL = 'INFO'
BLAZE_UI_HOST = os.environ.get('BLAZE_UI_HOST', 'localhost')
BLAZE_UI_WS_PORT = os.environ.get('BLAZE_UI_WS_PORT', '31337')

BLAZE_WS_SHUTDOWN = 'SHUTDOWN'

log = _logging.getLogger(__name__)


def register_for_function(action, description):
    def wrapper(f):
        PluginCommand.register_for_function(action, description, f)
        return f

    return wrapper


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

    def send(self, msg: BinjaToServer):
        self.blaze.send(self.bv, msg)


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

    def ensure_instance(self, bv: BinaryView) -> BlazeInstance:
        if (instance := BlazePlugin.instances.get(bv.file.filename)) is not None:
            return instance

        instance = BlazeInstance(bv, self)
        BlazePlugin.instances[bv.file.filename] = instance
        return instance

    def send(self, bv: BinaryView, msg: BinjaToServer) -> None:
        self._init_thread()
        self.ensure_instance(bv)
        new_msg = BinjaMessage(bvFilePath=bv.file.filename, action=msg)
        log.debug('enqueueing %s', new_msg)
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

            instance: Optional[BlazeInstance] = self.instances.get(msg['bvFilePath'])
            if instance is None:
                log.error("couldn't find blaze instance in mapping for %s", msg)
                continue

            log.debug('Blaze: received %r', msg)
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
            log.debug('sending %r', json_msg)

            try:
                await websocket.send(json_msg)
            except:
                return
            log.debug('sent')
            self.out_queue.task_done()

    def message_handler(self, instance: BlazeInstance, msg: ServerToBinja) -> None:
        tag = msg['tag']
        log.debug('Got message: %s', json.dumps(msg, indent=2))

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
    blaze.send(bv, BinjaToServer(tag='BSCfgNew', startFuncAddress=func.start))


def listen_start(bv):
    pass


def listen_stop(bv):
    pass


# PluginCommand.register_for_medium_level_il_instruction(actionSendInstruction, "Send Instruction", send_instruction)

# UIAction.registerAction(actionSayHello, "CTRL+1")
# UIAction.registerAction(sendEndAction, "CTRL+2")
# UIAction.registerAction(findPathAction, "CTRL+3")
