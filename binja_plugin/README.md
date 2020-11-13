# Blaze Binja plugin

Messages can be sent with `blaze.send` and all messages are handled in `message_handler`.

Add or modify the message actions that the plugin can take by changing the `ServerToBinja` and `BinjaToServer` types in the `../server` project.


## Known Requirements:

```
pip install asyncio websockets json
```

