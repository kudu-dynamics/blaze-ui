from binaryninja import PluginCommand, HighlightStandardColor, log_info, log_error
import socket
import struct
from binaryninjaui import UIAction
from binaryninja.function import DisassemblyTextRenderer, InstructionTextToken
from binaryninja.flowgraph import FlowGraph, FlowGraphNode
from binaryninja.enums import InstructionTextTokenType
from binaryninjaui import FlowGraphWidget, ViewType
import sys
import os
import os.path
import asyncio
import websockets
import json


IP_ADDR = "127.0.0.1"
TCP_PORT = 31337

def fwd_path_start(bv, instruction):
        global pathStart
        if pathStart is not None:
                bv.get_functions_at(pathStart.function_start)[0].set_auto_instr_highlight(pathStart.inst_addr, HighlightStandardColor.NoHighlightColor)
        pathStart = PathInfo(instruction)
        instruction.function.source_function.set_auto_instr_highlight(instruction.address, HighlightStandardColor.GreenHighlightColor)


def fwd_path_end(bv, instruction):
        global pathEnd
        if pathEnd is not None:
                bv.get_functions_at(pathEnd.function_start)[0].set_auto_instr_highlight(pathEnd.inst_addr, HighlightStandardColor.NoHighlightColor)
        pathEnd = PathInfo(instruction)
        instruction.function.source_function.set_auto_instr_highlight(instruction.address, HighlightStandardColor.BlueHighlightColor)

taggedBlocks = []

def find_path(bv):
        global taggedBlocks
        log_info("Path Start: %x %x" % (pathStart.index, pathStart.function_start))
        log_info("Path End: %x %x" % (pathEnd.index, pathEnd.function_start))
        msg = path_pb2.PathRequest()
        msg.start_func_addr= pathStart.function_start
        msg.start_mlil_ssa_index = pathStart.index
        msg.end_func_addr = pathEnd.function_start
        msg.end_mlil_ssa_index = pathEnd.index
        serialized_msg = msg.SerializeToString()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.connect((IP_ADDR, TCP_PORT))
        sock.send(struct.pack(">L", len(serialized_msg)))
        sock.send(serialized_msg)

        log_info("waiting for response")
        size = struct.unpack(">L", sock.recv(4))[0]
        data = b''
        
        #TODO: do this in a blocking thread so it doesn't hang binja
        while len(data) < size:
              data = data + sock.recv(size - len(data))
        #data = sock.recv(size)
        sock.close()
        pathResponse = path_pb2.PathResponse()
        pathResponse.ParseFromString(data)
        if not pathResponse.valid:
                log_error("No result")
        for bb in pathResponse.basic_blocks:
                func = bv.get_functions_at(bb.func_addr)
                for block in func[0].mlil.ssa_form.basic_blocks:
                        if block.start == bb.mlil_ssa_start_index:
                                taggedBlocks.append((bb.func_addr, block.start))
                                block.set_auto_highlight(HighlightStandardColor.RedHighlightColor)

# TODO: doesn't de-highlight blocks on path
def clear_paths(bv):
        global pathStart
        global pathEnd
        global taggedBlocks
        if pathStart is not None:
                for func in bv.get_functions_at(pathStart.function_start):
                        func.set_auto_instr_highlight(pathStart.inst_addr, HighlightStandardColor.NoHighlightColor)
                        pathStart = None
        if pathEnd is not None:
                for func in bv.get_functions_at(pathEnd.function_start):
                        func.set_auto_instr_highlight(pathEnd.inst_addr, HighlightStandardColor.NoHighlightColor)
                        pathEnd = None
        for tblock in taggedBlocks:
                func = bv.get_functions_at(tblock[0])
                for block in func[0].mlil.ssa_form.basic_blocks:
                        if block.start == tblock[1]:
                                block.set_auto_highlight(HighlightStandardColor.NoHighlightColor)
        taggedBlocks = []

async def hello():
    uri = "ws://127.0.0.1:31337"
    async with websockets.connect(uri) as websocket:
        msg = json.dumps({'tag': 'TextMessage', 'message': 'this is Bilbo'})
        await websocket.send(msg)
        print(f"> {msg}")

        greeting = json.loads(await websocket.recv())
        bilbo = greeting['message']
        print(f"< {bilbo}")



def say_hello(bv):
        
        return pathStart is not None and pathEnd is not None

def listen_start(bv):
        pass

def listen_stop(bv):
        pass

actionSayHello = "Blaze\\Say Hello"
actionSendInstruction = "Blaze\\Send Instruction"

PluginCommand.register(actionSayHello, "Say Hello", say_hello)
PluginCommand.register_for_medium_level_il_instruction(actionSendInstruction, "Send Instruction", send_instruction)

# UIAction.registerAction(setStartAction, "CTRL+1")
# UIAction.registerAction(sendEndAction, "CTRL+2")
# UIAction.registerAction(findPathAction, "CTRL+3")
