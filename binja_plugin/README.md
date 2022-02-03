# Blaze plugin for BinaryNinja

Messages can be sent with `blaze.send` and all messages are handled in `message_handler`.

Add or modify the message actions that the plugin can take by changing the `ServerToBinja` and `BinjaToServer` types in the `../server` project.


## Known Requirements:

`pip install websockets requests`


## Installation


### Manual Method

Symlink the `src/blaze` directory in binja's plugins directory.

```sh
$ ln -s <THIS_REPO>/binja_plugin/src/blaze ~/.binaryninja/plugins/blaze
# activate your virtualenv which you use for Binary Ninja, or otherwise use the
# `pip` that corresponds to the python installation which Binary Ninja is configured
# to use
$ pip install websockets requests
```

### Repository Method

The plugin is built and served as part of the docker-compose.yml configuration in the parent directory.

```sh
$ cd ..
$ docker-compose pull
$ docker-compose up
```

Building of the plugin with the `package_plugins.sh` script requires additional dependencies:

`pip install toml-cli build pkginfo`.


To build and serve `plugins.json`:
1. run: `./package_plugin.sh http://localhost:8000` (or wherever the plugin will be served from)
2. `cd ./dist && python3 -m http.server`
3. In BinaryNinja settings, set `http://localhost:8000/` as the Unofficial 3rd Party Plugin Repo URL
4. Blaze should appear in the Plugin Manager (ctrl-shift-m)

If it doesn't show up, try restarting BinaryNinja. The python server should get a hit for `/plugins.json`.

#### Troubleshooting

One known problem is BinaryNinja caching local copies of 3rd party repositories when renaming the 3rd party repo being used in the settings, leading to duplicate entries in the plugin manager. If renaming the 3rd party repo (or to be safe, changing server location), make sure to delete the local directory in `.binaryninja/repositories/<repo_name>` and remove the entry from
`.binaryninja/repositories/plugin_status.json`.
