from binaryninja import PluginCommand, HighlightStandardColor, log_info, log_error, BinaryView
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

IP_ADDR = "127.0.0.1"
TCP_PORT = 31337

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
        log_info("adding outbound msg to queue")
        new_msg = {"_bvFilePath" : bv.file.filename, "_action" : msg}
        self.out_queue.put(new_msg)
        # asyncio.ensure_future(self.out_queue.put(new_msg))
        # x = self.loop.create_task(self.out_queue.put(new_msg))
        

def hello2():
    uri = "ws://127.0.0.1:31337"

    websocket = websockets.connect(uri)
    log_info("Connected to web socket")
    msg = json.dumps({'tag': 'TextMessage', 'message': 'this is Bilbo'})
    websocket.send(msg)
    log_info(f"> {msg}")
    greeting = json.loads(websocket.recv())
    bilbo = greeting['message']
    log_info(f"< {bilbo}")
        
async def hello():
    uri = "ws://127.0.0.1:31337"

    async with websockets.connect(uri) as websocket:
        msg = json.dumps({'tag': 'TextMessage', 'message': 'this is Bilbo'})
        await websocket.send(msg)
        log_info(f"> {msg}")

        greeting = json.loads(await websocket.recv())
        bilbo = greeting['message']
        log_info(f"< {bilbo}")

async def recv_loop(websocket):
    while True:
        msg = json.loads(await websocket.recv())
        log_info(f"got {msg}")

async def send_loop(loop, websocket, out_queue):
    while True:
        msg = await loop.run_in_executor(None, out_queue.get)
        await websocket.send(json.dumps(msg))
        out_queue.task_done()
        log_info(f"sent {msg}")
        
async def main_websocket_loop(loop, out_queue):
    uri = "ws://127.0.0.1:31337"

    async with websockets.connect(uri) as websocket:
        consumer_task = asyncio.ensure_future(
            recv_loop(websocket))
        producer_task = asyncio.ensure_future(
            send_loop(loop, websocket, out_queue))
        done, pending = await asyncio.wait(
            [consumer_task, producer_task],
            return_when=asyncio.FIRST_COMPLETED,
        )
        for task in pending:
            task.cancel()
        
        # log_info("connected to websocket")
        # asyncio.gather(recv_loop(websocket), send_loop(websocket, out_queue))


class MainWebsocketThread(BackgroundTaskThread):
    def __init__(self, bv_mapping, event_loop, out_queue):
        BackgroundTaskThread.__init__(self, "", False)
        self.loop = event_loop
        self.out_queue = out_queue
        
    def run(self):
        self.loop.create_task(main_websocket_loop(self.loop, self.out_queue))
        self.loop.run_forever()

blaze = BlazeIO(asyncio.get_event_loop())

def say_hello(bv):
    global blaze
    blaze.send(bv, {'tag': 'BSTextMessage', 'message': 'this is Bilbo'})
    # loop = asyncio.get_event_loop()
    # t = MainWebsocketThread(bv, loop, None)
    # t.start()



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
