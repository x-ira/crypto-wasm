#!/bin/bash

PROJECT="ecdh"
TARGET="wasm32-unknown-unknown"
APP="target/$TARGET/release/$PROJECT.wasm"

# build release for target
cargo b --target=$TARGET -r

wasm-bindgen --out-dir ./out --target web $APP

cp out/$PROJECT.js ../arc/web/public/lib/
cp out/"$PROJECT"_bg.wasm ../arc/web/public/lib/

