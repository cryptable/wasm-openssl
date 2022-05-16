all: hello.html

hello.html: hello.cpp ssl.cpp
#	emcc -L../openssl -I../openssl/include ssl.cpp -s WASM=1 -s RESERVED_FUNCTION_POINTERS=10 -o hello.html -lssl -lcrypto  
#	emcc -L../openssl -I../openssl/include ssl.cpp -o hello.html -lssl -lcrypto -s WASM=1 -s RESERVED_FUNCTION_POINTERS=10 -s "EXPORTED_FUNCTIONS=['_doTest']" -s 'EXPORTED_RUNTIME_METHODS=["ccall", "cwrap"]'
	emcc -v -O2 -L../openssl -I../openssl/include ssl.cpp -lcrypto -lssl -o hello.html -s WASM=1 -s RESERVED_FUNCTION_POINTERS=10 -s "EXPORTED_FUNCTIONS=['_doTest']" -s 'EXPORTED_RUNTIME_METHODS=["ccall", "cwrap", "addFunction"]'

clean:
	rm hello.html hello.wasm hello.js ssl.o
