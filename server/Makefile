.PHONY: build help test copy-tests hlint docs clean

BUILD_TYPE ?= dev
STACK_OPTIONS ?=
STACK_BUILD_OPTIONS ?=
STACK_HADDOCK_OPTIONS ?=

export BLAZE_UI_HOST ?= localhost
export BLAZE_UI_WS_PORT ?= 31337
export BLAZE_UI_HTTP_PORT ?= 31338
export BLAZE_UI_SQLITE_FILEPATH ?= $(HOME)/.local/share/blaze/blaze.sqlite
export BLAZE_UI_BNDB_STORAGE_DIR ?= $(HOME)/.local/share/blaze/bndbs

stack_options_dev := --stack-yaml stack-dev.yaml $(STACK_OPTIONS)
stack_options_release := $(STACK_OPTIONS)
stack_options := $(stack_options_$(BUILD_TYPE))

stackage_snapshot := $(shell grep -oE '^resolver: .*$$' stack.yaml | sed -E -e 's/resolver:\s*//' -e 's/\s*$$//')
haddock_remote := https://www.stackage.org/haddock/${stackage_snapshot}/

# Ideally we'd include all of our projects but this creates too large an artifact (>100MB) for our gitlab pages instance
# HADDOCK_CP_COMMAND := cp -ar $$(stack path --haddock ${HADDOCK_ARGS} --local-doc-root)/{binary-analysis-*,binaryninja-*,blaze-*,blaze-ui-server-*,doc-index*,index.html,*.css,*.js,*.png} docs/
HADDOCK_CP_COMMAND := cp -ar $$(stack $(stack_options) path --haddock ${STACK_HADDOCK_OPTIONS} --local-doc-root)/{blaze-*,blaze-ui-server-*,doc-index*,index.html,*.css,*.js,*.png} docs/

build:
	stack $(stack_options) build --test --no-run-tests $(STACK_BUILD_OPTIONS)

run:
	stack $(stack_options) run blaze-server

test: build
	../.ci/scripts/run_test.py $$(stack $(stack_options) path --dist-dir)/build/blaze-server-general-test/blaze-server-general-test

copy-tests: build
	if ! [ -d "$${TEST_BIN_DEST_DIR}" ]; then echo "TEST_BIN_DEST_DIR does not exist or is not a directory" >&2; exit 2; fi
	cp $$(stack $(stack_options) path --dist-dir)/build/blaze-server-general-test/blaze-server-general-test "$${TEST_BIN_DEST_DIR}"

hlint:
	hlint src test

docs:
	stack $(stack_options) haddock $(STACK_HADDOCK_OPTIONS)
	rm -rf docs/
	mkdir -p docs
	bash -c 'shopt -s nullglob && ${HADDOCK_CP_COMMAND}'
	find docs/ -name '*.html' -type f -print0 | xargs -0 sed -i 's|<a href="\.\./\([^/]\+\)|<a href="'"${haddock_remote}"'\1|g'
	find docs/ -maxdepth 1 -type d -printf '%P\n' | \
		while read d; do \
			find docs/ -name '*.html' -type f -exec sed -i 's|<a href="'"${haddock_remote}$$d"'/docs|<a href="../'"$$d"'|g' {} \; ; \
		done

clean:
	stack $(stack_options) clean
