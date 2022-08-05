# Blaze UI

This project provides a UI for using Blaze to assist in reverse engineering and vulnerability research tasks.

It consists of three components:

* *Binary Ninja UI Plugin* - communicates with server, sending UI interaction events, and receiving updates
* *Web UI* - javascript front-end where we display blaze-specific info
* *Blaze Server* - backend between the Binary Ninja plugin and Blaze, workhorse for Blaze services

## Requirements

* Binary Ninja `3.1.3469` (stable/release)
* Python `^3.8`
  * It is recommended you use a virtualenv. [See here for more instructions][wiki-virtualenv]
* Either
  * [Blaze](../../../../blaze), and all its transitive deps (so Haskell Stack, binaryninja-api, binaryninja-haskell, etc), or
  * Docker and docker-compose (or any other OCI container executor)

[wiki-virtualenv]: https://wiki.kududyn.com/s/bhc9a4h4cn3e3taiv8b0/aawg-analysis/d/btvjpj6l9dtngo7latgg/binary-ninja?currentPageId=c23hthul9dtilsqib800

## Installation

### Binary Ninja license

A license to Binary Ninja must be provided.
When running locally (e.g. through `stack`), Blaze will use the license within the [Binary Ninja user folder](https://docs.binary.ninja/getting-started.html#user-folder) (e.g. `~/.binaryninja/license.dat`).
When running under Docker, you can either copy `license.dat` into the root of this repository (in which case Docker Compose will automatically copy it into the appropriate containers), or you can export the environment variable `BLAZE_BINJA_LICENSE_FILE` (e.g. `export BLAZE_BINJA_LICENSE_FILE=~/.binaryninja/license.dat`) when running `docker-compose up` (see below).

### Plugin Installation

Follow the installation instructions for the binja plugin [here](./binja_plugin/README.md)


## Running the Blaze server

You can use either Stack (useful during development) or Docker (useful in
production) to run the backend server. Additionally, to install the UI plugin in
BinaryNinja, you can use Docker to serve the plugin.

### Using Stack

Build server:
```sh
$ cd server
$ make
$ mkdir -p "$HOME/.local/share/blaze"
```

Run server (using default values of `BLAZE_*` environment variables):
```sh
$ make run
```

Run server (overriding environment variables):
```sh
$ make run \
  BLAZE_UI_HOST=localhost \
  BLAZE_UI_WS_PORT=31337 \
  BLAZE_UI_HTTP_PORT=31338 \
  BLAZE_UI_SQLITE_FILEPATH="$HOME/.local/share/blaze/blaze.sqlite" \
  BLAZE_UI_BNDB_STORAGE_DIR="$HOME/.local/share/blaze/bndbs"
```

And then start the plugin server:

- Edit docker-compose.yml if needed:
  - Forward the desired port for the wheel server
  - Edit `BLAZE_WHEEL_SERVER_URL` (most likely you'll want `http://localhost:$PORT`)
  - Switch between the GitLab (authoritative) repository or AWS ECR (fast) repository
-
  ```sh
  # Login, if needed
  $ docker login ${CI_REGISTRY}
  # Pull the latest prebuilt image ...
  $ docker-compose pull
  # ... or rebuild if local modifications have been made
  $ docker-compose build wheel-server
  # Start the service
  $ docker-compose up blaze-plugin-repository
  ```

### Using docker

- Edit docker-compose.yml if needed:
  - Forward the desired port for the wheel server
  - Edit `BLAZE_WHEEL_SERVER_URL` (most likely you'll want `http://localhost:$PORT`)
  - Forward the desired ports for the WebSocket and HTTP services
  - Switch between the GitLab (authoritative) repository or AWS ECR (fast) repository
  - Edit docker volume(s)

```sh
# Login, if needed
$ docker login ${CI_REGISTRY}

# Pull the latest prebuilt images ...
$ docker-compose pull
# ... or rebuild if local modifications have been made
$ docker-compose build --pull

# Copy your license file ...
$ cp ~/.binaryninja/license.dat
# ... or specify license file using environment variable
$ export BLAZE_BINJA_LICENSE_FILE=~/.binaryninja/license.dat

# Start the services
$ docker-compose up
```

## Installing Blaze in Binary Ninja

1. After starting the wheel server (which also functions as a BinaryNinja plugin repository), open BinaryNinja and edit these settings (`Edit > Preferences > Settings` or `Ctrl-,`):
   - `Plugin Manager > Unofficial 3rd Party Plugin Repository Display Name` can be set to anything. Example: `localhost`
   - `Plugin Manager > Unofficial 3rd Party Plugin Repository URL` should be the value of `BLAZE_WHEEL_SERVER_URL`
2. Open the Plugin Manager (`Edit > Preferences > Manage Plugins` or `Ctrl-Shift-M`), and `uninstall` any old version of Blaze
3. Restart Binary Ninja
4. Open the Plugin Manager again, `install` Blaze, then `enable` it
5. Set the following settings:
   - `Blaze > Unique Client ID` shouldn't need to be changed, but as a sanity check, it should already be set and begin with the local username followed by `_`
   - `Blaze > Blaze Host` should point at the host which is running the blaze server (e.g. `localhost`)
   - `Blaze > Blaze WebSocket Port` should be the value of `BLAZE_UI_WS_PORT` (`31337` by default)
   - `Blaze > Blaze HTTP Port` should be the value of `BLAZE_UI_HTTP_PORT` (`31338` by default)
6. Restart Binary Ninja

### Verifying installed Blaze version

After installing Blaze in Binary Ninja, in the Binary Ninja Python Console, run:

``` python
>>> from pathlib import Path
>>> print((Path(Kudu_Blaze.__file__).parent / 'METADATA').read_text())
```

You should see output like

```
Metadata-Version: 2.1
Name: blaze
Version: 0.1.0.65746
Summary: Blaze
Author: Kudu Dynamics
Requires-Python: >=3.6.1,<3.10
Classifier: Programming Language :: Python :: 3
Classifier: Programming Language :: Python :: 3.7
Classifier: Programming Language :: Python :: 3.8
Classifier: Programming Language :: Python :: 3.9
Requires-Dist: requests (>=2.26.0,<3.0.0)
Requires-Dist: typing-extensions (>=3.10.0,<4.0.0)
Requires-Dist: websockets (>=9.1,<10.0)
```

The `Version: 0.1.0.65746` line indicates that `pyproject.toml` set `version = "0.1.0"`, and that the unique build ID determined by the value of `CI_PIPELINE_ID` was `65746`.
You can then go to https://gitlab/blaze/blaze-ui/-/pipelines/65746 to determine which commit it came from.


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
