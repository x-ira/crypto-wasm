### Parepare & Build
```sh
cargo init --lib
cargo add wasm-bindgen
rustup target add wasm32-unknown-unknown

cargo build --target wasm32-unknown-unknown --release

cargo install wasm-bindgen-cli
# wasm-bindgen --out-dir ./out --target web target/wasm32-unknown-unknown/release/ecdh.wasm
wasm-pack build --target bundler --release # -t  
cd pkg
npm publish  # maybe need change the pkg name and version
npm version patch

```

### Test

### Pareparing
```
npm i vite-plugin-wasm

# vite.config.js
import wasm from "vite-plugin-wasm";
...
plugins: [
    wasm(),
  ]  
...
```

```js
import { Ecdh } from "ecdh-x25519-wasm";  //no need init
let ecdh = new Ecdh();
console.log(ecdh.pub_key);
```
