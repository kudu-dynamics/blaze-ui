stackage_snapshot := $(shell grep -oE '^resolver: .*$$' stack.yaml | sed -E -e 's/resolver:\s*//' -e 's/\s*$$//')
haddock_remote := https://www.stackage.org/haddock/${stackage_snapshot}/

# HADDOCK_ARGS := --no-haddock-hyperlink-source
HADDOCK_ARGS :=
STACK_OPTIONS ?=

# Ideally we'd include all of our projects but this creates too large an artifact (>100MB) for our gitlab pages instance
# HADDOCK_CP_COMMAND := cp -ar $$(stack path --haddock ${HADDOCK_ARGS} --local-doc-root)/{binary-analysis-*,binaryninja-*,blaze-*,blaze-ui-server-*,doc-index*,index.html,*.css,*.js,*.png} docs/
HADDOCK_CP_COMMAND := cp -ar $$(stack path --haddock ${HADDOCK_ARGS} --local-doc-root)/{blaze-*,blaze-ui-server-*,doc-index*,index.html,*.css,*.js,*.png} docs/

.PHONY: build optim help test submodule-init submodule-update hlint docs

build:
	stack build --test --no-run-tests --fast ${STACK_OPTIONS}

optim:
	stack clean
	$(MAKE) -C ../blaze optim
	stack build --test --no-run-tests --ghc-options=-O2 ${STACK_OPTIONS}

test: build
	.ci/scripts/run_test.py $$(stack path --dist-dir)/build/blaze-server-test/blaze-server-test

hlint:
	hlint src test

docs:
	stack haddock ${HADDOCK_ARGS}
	rm -rf docs/
	mkdir -p docs
	bash -c 'shopt -s nullglob && ${HADDOCK_CP_COMMAND}'
	find docs/ -name '*.html' -type f -print0 | xargs -0 sed -i 's|<a href="\.\./\([^/]\+\)|<a href="'"${haddock_remote}"'\1|g'
	find docs/ -maxdepth 1 -type d -printf '%P\n' | \
		while read d; do \
			find docs/ -name '*.html' -type f -exec sed -i 's|<a href="'"${haddock_remote}$$d"'/docs|<a href="../'"$$d"'|g' {} \; ; \
		done
