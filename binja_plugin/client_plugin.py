import asyncio
import json
import os
import os.path
import queue
import sys
import traceback
from typing import Any, Dict, Optional
import threading

import websockets
from binaryninja import (BinaryView, PluginCommand, log_error, log_info, log_warn, log_debug)

from .cfg import display_icfg

BLAZE_UI_HOST = os.environ.get('BLAZE_UI_HOST', 'localhost')
BLAZE_UI_WS_PORT = os.environ.get('BLAZE_UI_WS_PORT', '31337')

BLAZE_WS_SHUTDOWN = 'SHUTDOWN'


class BlazeIO():
    def __init__(self) -> None:
        self.thread: Optional[threading.Thread] = None
        self.bv_mapping: Dict[str, BinaryView] = {}  # {bvFilePath -> bv}

    def _init_thread(self) -> None:
        if not self.thread or not self.thread.is_alive():
            log_info('Blaze: Starting or restarting websocket thread')
            self.out_queue = queue.Queue()
            t = MainWebsocketThread(self.bv_mapping, self.out_queue)
            t.name = 'Blaze websocket thread'
            t.start()
            self.thread = t

    def shutdown(self) -> None:
        if self.thread and self.thread.is_alive():
            log_info('Blaze: shutdown: Shutting down')
            try:
                self.out_queue.put(BLAZE_WS_SHUTDOWN, timeout=1)
            except queue.Full:
                log_warn('Blaze: shutdown: websocket queue is full, cannot shutdown')
                return

            self.thread.join(timeout=1)
            if self.thread.is_alive():
                log_warn('Blaze: shutdown: websocket thread is still alive after timeout')


    def send(self, bv: BinaryView, msg: dict) -> None:
        self._init_thread()
        self.bv_mapping[bv.file.filename] = bv
        new_msg = {"bvFilePath": bv.file.filename, "action": msg}
        log_debug(f'Blaze: enqueueing {new_msg}')
        self.out_queue.put(new_msg)


class MainWebsocketThread(threading.Thread):
    def __init__(self, bv_mapping, out_queue) -> None:
        super().__init__()
        self.out_queue: queue.Queue = out_queue
        self.bv_mapping = bv_mapping

    def run(self) -> None:
        asyncio.run(main_websocket_loop(self.out_queue, self.bv_mapping))


def message_handler(bv: BinaryView, msg: Dict[str, Any]) -> None:
    tag = msg['tag']

    if tag == 'SBLogInfo':
        log_info(msg['message'])

    elif tag == 'SBLogWarn':
        log_warn(msg['message'])

    elif tag == 'SBLogError':
        log_error(msg['message'])

    elif tag == 'SBNoop':
        log_info(f"got Noop")

    elif tag == 'SBCfg':
        display_icfg(bv, msg['cfg'])

    else:
        log_error(f"Blaze: unknown message type: {tag}")


async def recv_loop(websocket, bv_mapping) -> None:
    async for ws_msg in websocket:
        try:
            msg = json.loads(ws_msg)
        except json.JSONDecodeError:
            log_error(f'Blaze: recv_loop: malformed message')
            log_error(traceback.format_exception_only(sys.last_type, sys.last_value))
            continue

        bv: Optional[BinaryView] = bv_mapping.get(msg['bvFilePath'])
        if bv is None:
            log_error(f"Blaze: recv_loop: couldn't find bv in mapping for {msg}")
            continue

        log_debug(f'Blaze: received {msg}')
        try:
            message_handler(bv, msg['action'])
        except Exception:
            log_warn(f"Blaze: message_handler: couldn't handle message")
            log_error(traceback.format_exc())
            continue


async def send_loop(websocket, out_queue) -> None:
    while True:
        msg = await asyncio.get_running_loop().run_in_executor(None, out_queue.get)
        if msg == BLAZE_WS_SHUTDOWN:
            out_queue.task_done()
            return

        json_msg = json.dumps(msg)
        log_debug(f'Blaze: sending {json_msg!r}')

        try:
            await websocket.send(json_msg)
        except:
            return
        log_debug('Blaze: sent')
        out_queue.task_done()


async def main_websocket_loop(out_queue, bv_mapping):
    uri = "ws://" + BLAZE_UI_HOST + ":" + BLAZE_UI_WS_PORT + "/binja"

    log_info('Blaze: connecting to websocket...')
    async with websockets.connect(uri) as websocket:
        log_info('Blaze: connected')
        consumer_task = asyncio.ensure_future(recv_loop(websocket, bv_mapping))
        producer_task = asyncio.ensure_future(send_loop(websocket, out_queue))
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

blaze = BlazeIO()


def say_hello(bv):
    global blaze
    blaze.send(bv, {'tag': 'BSTextMessage', 'message': 'this is Bilbo'})


def type_check_function(bv, func):
    global blaze
    blaze.send(bv, {'tag': 'BSTypeCheckFunction', 'address': func.start})


def start_cfg(bv, func):
    global blaze
    blaze.send(bv, {'tag': 'BSStartCfgForFunction', 'address': func.start})


def listen_start(bv):
    pass


def listen_stop(bv):
    pass


actionSayHello = "Blaze\\Say Hello"
actionSendInstruction = "Blaze\\Send Instruction"
actionTypeCheckFunction = "Blaze\\Type Check Function"
actionBlazeCfg = "Blaze\\Start CFG"

PluginCommand.register(actionSayHello, "Say Hello", say_hello)
PluginCommand.register_for_function(actionTypeCheckFunction, "Type Check Function",
                                    type_check_function)
PluginCommand.register_for_function(actionBlazeCfg, "Start CFG", start_cfg)

# PluginCommand.register_for_medium_level_il_instruction(actionSendInstruction, "Send Instruction", send_instruction)

# UIAction.registerAction(actionSayHello, "CTRL+1")
# UIAction.registerAction(sendEndAction, "CTRL+2")
# UIAction.registerAction(findPathAction, "CTRL+3")
