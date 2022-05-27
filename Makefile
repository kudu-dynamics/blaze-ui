.PHONY: build build-server test test-server copy-tests-server hlint docs docs-server clean clean-serer

build: build-server

build-server:
	$(MAKE) -C server build

test: test-server

test-server:
	$(MAKE) -C server test

run: run-server

run-server:
	$(MAKE) -C server run

copy-tests-server:
	$(MAKE) -C server copy-tests

hlint:
	$(MAKE) -C server hlint

docs: docs-server

docs-server:
	$(MAKE) -C server docs

clean: clean-server

clean-server:
	$(MAKE) -C server clean
