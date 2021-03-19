import enum
import asyncio
import json
import os
import os.path
import queue
from typing import Any, Dict, Optional
import threading

import websockets
from binaryninja import (BinaryView, PluginCommand)
from websockets.client import Connect, WebSocketClientProtocol

from .cfg import display_icfg

LOG_LEVEL = 'INFO'
BLAZE_UI_HOST = os.environ.get('BLAZE_UI_HOST', 'localhost')
BLAZE_UI_WS_PORT = os.environ.get('BLAZE_UI_WS_PORT', '31337')

BLAZE_WS_SHUTDOWN = 'SHUTDOWN'

import logging
log = logging.getLogger(__name__)
del logging

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
    def __init__(self, bv: BinaryView):
        self.bv: BinaryView = bv

class BlazePlugin():
    instances: Dict[str, BlazeInstance] = {}

    def __init__(self) -> None:
        self.websocket_thread: Optional[threading.Thread] = None

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

    @staticmethod
    def ensure_instance(bv: BinaryView) -> BlazeInstance:
        if (instance := BlazePlugin.instances.get(bv.file.filename)) is not None:
            return instance

        instance = BlazeInstance(bv)
        BlazePlugin.instances[bv.file.filename] = instance
        return instance

    def send(self, bv: BinaryView, msg: dict) -> None:
        self._init_thread()
        self.ensure_instance(bv)
        new_msg = {"bvFilePath": bv.file.filename, "action": msg}
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

    def message_handler(self, instance: BlazeInstance, msg: Dict[str, Any]) -> None:
        tag = msg['tag']

        if tag == 'SBLogInfo':
            log.info(msg['message'])

        elif tag == 'SBLogWarn':
            log.warn(msg['message'])

        elif tag == 'SBLogError':
            log.error(msg['message'])

        elif tag == 'SBNoop':
            log.info("got Noop")

        elif tag == 'SBCfg':
            display_icfg(instance.bv, msg['cfg'])

        else:
            log.error("Blaze: unknown message type: %s", tag)


def _get_or_set_loop() -> asyncio.AbstractEventLoop:
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        loop.set_debug(True)
        asyncio.set_event_loop(loop)

    return asyncio.get_running_loop()


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
    START_CFG = r'Blaze\Start CFG'


@register(Action.SAY_HELLO, 'Say Hello')
def say_hello(bv):
    blaze.send(bv, {'tag': 'BSTextMessage', 'message': 'this is Bilbo'})


@register_for_function(Action.TYPE_CHECK_FUNCTION, 'Type Check Function')
def type_check_function(bv, func):
    blaze.send(bv, {'tag': 'BSTypeCheckFunction', 'address': func.start})


@register_for_function(Action.START_CFG, 'Start CFG')
def start_cfg(bv, func):
    blaze.send(bv, {'tag': 'BSStartCfgForFunction', 'address': func.start})


def listen_start(bv):
    pass


def listen_stop(bv):
    pass

# PluginCommand.register_for_medium_level_il_instruction(actionSendInstruction, "Send Instruction", send_instruction)

# UIAction.registerAction(actionSayHello, "CTRL+1")
# UIAction.registerAction(sendEndAction, "CTRL+2")
# UIAction.registerAction(findPathAction, "CTRL+3")
