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

## Purescript client

See `/web/README.md`
