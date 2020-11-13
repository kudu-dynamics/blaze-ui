#!/usr/bin/env python

# WS client example

import asyncio
import websockets
import json

async def hello():
    uri = "ws://127.0.0.1:31337"
    async with websockets.connect(uri) as websocket:
        msg = json.dumps({'tag': 'TextMessage', 'message': 'this is Bilbo'})
        await websocket.send(msg)
        print(f"> {msg}")

        greeting = json.loads(await websocket.recv())
        bilbo = greeting['message']
        print(f"< {bilbo}")

asyncio.get_event_loop().run_until_complete(hello())
