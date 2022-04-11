.PHONY: build build-server help test test-server submodule-init submodule-update hlint docs docs-server

build: build-server

build-server:
	$(MAKE) -C server build

test: test-server

test-server:
	$(MAKE) -C server test

submodule-init:
	git submodule init
	git submodule update

submodule-update:
	git submodule update --remote --merge

hlint:
	$(MAKE) -C server hlint

help:
	@cat Makefile

docs: docs-server

docs-server:
	$(MAKE) -C server docs
