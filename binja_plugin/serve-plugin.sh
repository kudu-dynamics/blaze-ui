#!/bin/bash

docker build . -t blaze-plugin-server

docker run --rm -d -p 8000:3000 blaze-plugin-server
