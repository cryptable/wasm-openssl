OpenSSL crypto library in the browser
=====================================

Introduction
------------

This is POC to run the crypto library OpenSSL as webassembly in your browser. The demo in the index.html will generate a RSA keypair and create a self-signed x509 certificate. 
In another project, the support for digital signatures hes been proven.
Why? 
1) OpenSSL is an actively supported crypto library, where you can be quite certain no bugs or side channel attacks are present. Though it hasn't been proven for the WASM release. This is research thema.
2) It runs in the browser, so no confidential information is uploaded to a server to perform the action. You can still implement server-side signing by implementing a Openssl-engine.

The key generation is quite slow and uses seed collection from the browser and WASM, which can be not realy secure. Think about this!

Compilation
-----------

1) Install [emscripten](https://emscripten.org/) and follow the [Getting Started](https://emscripten.org/docs/getting_started/index.html) to set it up.
2) Checkout [OpenSSL](https://github.com/openssl/openssl) and checkout the latest release. When you go in the openssl directory, check that you emscripten 'emcc' works.
3) In the directory of this project is a shell script to configure and compile Openssl. Copy the script into the openssl directory and run it.

It will create in the openssl-directory a libssl.a and a libcrypto.a file, which you can use build your openssl based WASM projects.

This demo project shows the usage of openssl. To compile it, run:
```
emmake make
```

If it doesn't compile, check the directory for the libssl.a and libcrypto.a in the make file.

Testing
-------

You'll need python to test it. The project has a small server (server.py). Start it by:

```
python server.py
```

Goto [http://localhost:8000/index.html](http://localhost:8000/index.html) and open your javascript console. You'll have to wait a minute or 2 to let the script generate the keys. The signing is way more faster.