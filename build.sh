#!/bin/sh

go build -ldflags '-s -w -extldflags "-static"' -gcflags=-G=3 -o nosakouko.wasm
