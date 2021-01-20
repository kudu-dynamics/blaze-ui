# Blaze UI

This project provides a UI for using Blaze to assist in reverse engineering and vulnerability research tasks.

It consists of three components:

* *Binja Plugin* - sends binja UI events to server, recvs messages to change UI
* *Web UI* - javascript front-end where we display blaze-specific info
* *Blaze Server* - middleman between plugin and web, workhorse for Blaze services

## Installation

Set two env vars:

```
export BLAZE_UI_HOST="localhost"
export BLAZE_UI_WS_PORT="31337"
export BLAZE_UI_HTTP_PORT="31338"
```

Symbolically link binja plugin, `~/.binaryninja/plugins/blaze` to the `blaze-ui/binja_plugin` folder.

Install the `websockets` Python package for the Python installation used by Binary Ninja.

Run server:

```
cd server
stack run
```

## Purescript client

See `/web/README.md`
