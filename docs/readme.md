```sh
  cargo init --lib
  cargo add wasm-bindgen
  rustup target add wasm32-unknown-unknown

  cargo build --target wasm32-unknown-unknown --release

  cargo install wasm-bindgen-cli
  wasm-bindgen --out-dir ./out --target web target/wasm32-unknown-unknown/release/ecdh.wasm
```



```js
    <script type="module">
        import init, { share_key } from "./out/ecdh.js"; //ecdh_bg.wasm is also required
        init().then(() => {
            console.log(share_key());
        });
    </script>
```
