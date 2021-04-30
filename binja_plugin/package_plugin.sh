#!/bin/bash

# something to consolidate plugin packaging and distribution process
# collects all necessary artifacts into ./dist including:
# - <plugin>.whl
# - <plugin>.tar.gz
# - plugins.json
# - plugin.json
# 
# TODO:
# - more robust arg parsing (incl user-defined dist dir)
# - reduce duplication between JSONs and setup.cfg
# - containerize for portability? CI/CD?
# 
# if you're reading this and want to test the result, a quick and dirty way is to:
# 1. run this as: `./package_plugin.sh http://localhost:8000` (or whatever)
# 2. in ./dist, run: `python3 -m http.server`
# 3. in binja options, set `http://localhost:8000/` as the Unofficial 3rd Party Plugin Repo URL
# 4. Blaze should appear in the Plugin Manager


DIST_DIR=./dist
PLUGIN_JSON=plugin.json
PLUGINS_JSON=plugins.json

package_url=http://localhost:8000 # just a default
if [[ -z $1 ]]; then
  echo "no package url used... using default"
else
  package_url=$1
  echo "using supplied package url..."
fi

echo "package_url=$package_url"

# 0. Cleanup Dist
# ===============

echo "clearing $DIST_DIR ..."
echo "rm -rf $DIST_DIR/*"
rm -rf "${DIST_DIR:?}"/*


# 1. Build wheel
# ==============

# make sure build packages are present
python3 -m pip install --upgrade build pkginfo
# actually build the wheel
python3 -m build -o $DIST_DIR

# 1.1 Get wheel name
wheel_name="$(ls -1t $DIST_DIR | grep whl | head -n 1)"
# 1.2 Get wheel dependencies
dependencies="$(pkginfo $DIST_DIR/$wheel_name -f requires_dist --single --sequence-delim=\\\n)"


# 2. Copy JSONs into dist
# ====================

echo "cp $PLUGIN_JSON $DIST_DIR/$PLUGIN_JSON ..."
cp $PLUGIN_JSON $DIST_DIR/$PLUGIN_JSON
echo "cp $PLUGINS_JSON.template $DIST_DIR/$PLUGINS_JSON ..."
cp $PLUGINS_JSON.template $DIST_DIR/$PLUGINS_JSON


# 3. Search and replace
# =====================

# I'm assuming ` is a fine delimiter that won't show up in these variables...
# please don't use ` in your package url <3
sed -i "s\`%PACKAGEURL%\`$package_url/$wheel_name\`" $DIST_DIR/$PLUGINS_JSON
sed -i "s\`%DEPENDENCIES%\`$dependencies\`" $DIST_DIR/$PLUGINS_JSON
