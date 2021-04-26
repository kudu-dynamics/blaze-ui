# Blaze UI

This project provides a UI for using Blaze to assist in reverse engineering and vulnerability research tasks.

It consists of three components:

* *Binary Ninja UI Plugin* - communicates with server, sending UI interaction events, and receiving updates
* *Web UI* - javascript front-end where we display blaze-specific info
* *Blaze Server* - backend between the Binary Ninja plugin and Blaze, workhorse for Blaze services

## Requirements

* Binary Ninja `^2.3.2753-dev`
* Python `^3.8`
  * It is recommended you use a virtualenv. [See here for more instructions][wiki-virtualenv]
* Either
  * [Blaze](../../../../blaze), and all its transitive deps (so Haskell Stack, binaryninja-api, binaryninja-haskell, etc), or
  * Docker (or any other OCI container executor)

[wiki-virtualenv]: https://wiki.kududyn.com/s/bhc9a4h4cn3e3taiv8b0/aawg-analysis/d/btvjpj6l9dtngo7latgg/binary-ninja?currentPageId=c23hthul9dtilsqib800

## Installation

```sh
$ ln -s <THIS_REPO>/binja_plugin ~/.binaryninja/plugins/blaze
# activate your virtualenv which you use for Binary Ninja, or otherwise use the
# `pip` that corresponds to the python installation which Binary Ninja is configured
# to use
$ pip install websockets
```

## Running server

### Using Stack

```sh
$ cd server
$ stack build
$ stack run localhost 31337 31338
```

### Using docker

```sh
$ docker run --pull --rm -it \
    -v $HOME:$HOME \
    -p 31337:31337 \
    -p 31338:31338 \
    ${CI_REGISTRY}/${CI_PROJECT_NAMESPACE}/blaze-ui/blaze-service/squashed \
    /blaze/bin/blaze-server 0.0.0.0 31337 31338
```

## Using Blaze

- Open Binary Ninja, and open a binary
- If this is your first time running the Blaze plugin in Binary Ninja, or the ICFG view
  is hidden, click View > Other Docks > Show Blaze ICFG. This will open a dock widget,
  which you can drag around within Binary Ninja, or drag off-screen to pop out of the
  main Binary Ninja window.
- Find a function which you wish to begin exploration from, then right click > Plugins >
  Blaze > Start CFG. Once the server responds back, you will see the ICFG (which initially
  is just a CFG) displayed in the "Blaze ICFG" widget.
- Call-sites will be highlighted yellow. They can be double-clicked to expand that call-site.
  This introduces a subgraph where the Call node was, which represents the CFG of the callee.
  Additionally, two extra nodes will be introduced at the interface between the caller and callee:
  - An `EnterFunc` node will be introduced which relates the arguments passed at this call-site
    to the callee's corresponding parameters
  - A `LeaveFunc` node will be introduced which relates the return value of the callee with the
    caller's variable which is assigned the return value of the call, if there is such a variable
- Wherever there is a pair of conditional edges, one can be double-clicked on to "prune" that edge
  away. This essentially says "I want this edge to be impossible". Blaze will then remove that
  edge and any newly unreachable blocks, and (in a future version) update the solver
  with this new information to propagate new constraints

## Purescript client

See `/web/README.md`
