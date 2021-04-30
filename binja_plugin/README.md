# Blaze Binja plugin

Messages can be sent with `blaze.send` and all messages are handled in `message_handler`.

Add or modify the message actions that the plugin can take by changing the `ServerToBinja` and `BinjaToServer` types in the `../server` project.


## Known Requirements:

`pip install websockets`


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

