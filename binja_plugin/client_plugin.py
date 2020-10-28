from binaryninja import PluginCommand, HighlightStandardColor, log_info, log_error, log_warn, BinaryView
import socket
import struct
from binaryninjaui import UIAction
from binaryninja.function import DisassemblyTextRenderer, InstructionTextToken
from binaryninja.flowgraph import FlowGraph, FlowGraphNode
from binaryninja.enums import InstructionTextTokenType
from binaryninjaui import FlowGraphWidget, ViewType
from binaryninja.plugin import BackgroundTaskThread
import sys
import os
import os.path
import asyncio
import websockets
import json
import queue

BLAZE_UI_HOST = os.environ.get('BLAZE_UI_HOST', 'localhost')
BLAZE_UI_WS_PORT = os.environ.get('BLAZE_UI_WS_PORT', '31337')

class BlazeIO():
    def __init__(self, event_loop):
        self.thread = None
        self.loop = event_loop
        self.bv_mapping = {} # {bvFilePath -> bv}
        self.out_queue = queue.Queue()
        
    def __init_thread(self):
        if not self.thread:
            t = MainWebsocketThread(self.bv_mapping, self.loop, self.out_queue)
            t.start()
            self.thread = t

    def send(self, bv, msg):
        self.__init_thread()
        self.bv_mapping[bv.file.filename] = bv
        new_msg = {"_bvFilePath" : bv.file.filename, "_action" : msg}
        self.out_queue.put(new_msg)
        

def message_handler(bv, msg):
    tag = msg['tag']

    if tag == 'SBLogInfo':
        # log_info(f"Blaze: {msg['message']}")
        log_info(msg['message'])
        
    elif tag == 'SBLogWarn':
        # log_warn(f"Blaze: {msg['message']}")
        log_warn(msg['message'])

    elif tag == 'SBLogError':
        # log_error(f"Blaze: {msg['message']}")
        log_error(msg['message'])
        
    elif tag == 'SBNoop':
        log_info(f"got Noop")

    else:
        log_info(f"unknown message type")    
    return

async def recv_loop(websocket, bv_mapping):
    while True:
        msg = json.loads(await websocket.recv())
        # log_info(f"recv {msg}")
        try:
            bv = bv_mapping[msg['_bvFilePath']]
            message_handler(bv, msg['_action'])
        except:
            log_warn(f"recv_loop: couldn't find bv in mapping for {msg}")
                     
            
async def send_loop(loop, websocket, out_queue):
    while True:
        msg = await loop.run_in_executor(None, out_queue.get)
        await websocket.send(json.dumps(msg))
        out_queue.task_done()
        # log_info(f"sent {msg}")

async def main_websocket_loop(loop, out_queue, bv_mapping):
    uri = "ws://" + BLAZE_UI_HOST + ":" + BLAZE_UI_WS_PORT + "/binja"

    async with websockets.connect(uri) as websocket:
        consumer_task = asyncio.ensure_future(
            recv_loop(websocket, bv_mapping))
        producer_task = asyncio.ensure_future(
            send_loop(loop, websocket, out_queue))
        done, pending = await asyncio.wait(
            [consumer_task, producer_task],
            return_when=asyncio.FIRST_COMPLETED,
        )
        for task in pending:
            task.cancel()
        

class MainWebsocketThread(BackgroundTaskThread):
    def __init__(self, bv_mapping, event_loop, out_queue):
        BackgroundTaskThread.__init__(self, "", False)
        self.loop = event_loop
        self.out_queue = out_queue
        self.bv_mapping = bv_mapping

    def run(self):
        self.loop.create_task(main_websocket_loop(self.loop, self.out_queue, self.bv_mapping))
        self.loop.run_forever()

blaze = BlazeIO(asyncio.get_event_loop())

def say_hello(bv):
    global blaze
    blaze.send(bv, {'tag': 'BSTextMessage', 'message': 'this is Bilbo'})

def listen_start(bv):
    pass

def listen_stop(bv):
    pass

actionSayHello = "Blaze\\Say Hello"
actionSendInstruction = "Blaze\\Send Instruction"

PluginCommand.register(actionSayHello, "Say Hello", say_hello)
# PluginCommand.register_for_medium_level_il_instruction(actionSendInstruction, "Send Instruction", send_instruction)

# UIAction.registerAction(actionSayHello, "CTRL+1")
# UIAction.registerAction(sendEndAction, "CTRL+2")
# UIAction.registerAction(findPathAction, "CTRL+3")
