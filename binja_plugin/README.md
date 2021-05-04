# Blaze Binja plugin

Messages can be sent with `blaze.send` and all messages are handled in `message_handler`.

Add or modify the message actions that the plugin can take by changing the `ServerToBinja` and `BinjaToServer` types in the `../server` project.


## Known Requirements:

`pip install websockets requests`


## Installation


### Manual Method

Symlink the `manual-install` directory in binja's plugins directory.

```sh
$ ln -s <THIS_REPO>/binja_plugin/manual-install ~/.binaryninja/plugins/blaze
# activate your virtualenv which you use for Binary Ninja, or otherwise use the
# `pip` that corresponds to the python installation which Binary Ninja is configured
# to use
$ pip install websockets
```


### Repository Method

For a quick and dirty test of 3rd party repository usage in Binja:
1. run: `./package_plugin.sh http://localhost:8000` (or wherever the plugin will be served from)
2. `cd ./dist && python3 -m http.server`
3. in binja options, set `http://localhost:8000/` as the Unofficial 3rd Party Plugin Repo URL
4. Blaze should appear in the Plugin Manager (ctrl-shift-m)

If it doesn't show up, try restarting binja. The python server should get a hit for `/plugins.json`.

Alternately, to serve from a docker image:

```sh
docker build . -t blaze-plugin-server

docker run --rm -p 8000:3000 blaze-plugin-server
```

To tie this all together, assuming a built server image:

```sh
SERVE_PLUGIN_PORT=8000
./package_plugin.sh http://localhost:$SERVE_PLUGIN_PORT
docker run --rm -d -p $SERVE_PLUGIN_PORT:3000 blaze-plugin-server
```

#### Troubleshooting

One problem I ran into was binja retaining local copies of 3rd party repositories when renaming the 3rd party repo being used in the settings, leading to duplicate entries in the plugin manager. If renaming the 3rd party repo (or to be safe, changing server location), make sure to delete the local directory in `.binaryninja/repositories/<repo_name>` and remove the entry from
`.binaryninja/repositories/plugin_status.json`.
