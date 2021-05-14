.PHONY: python go

install-rust:
	cargo build --release
	sudo cp target/release/libudbserver.so /usr/lib
	sudo ldconfig

ensure-%:
	mkdir -p bindings/$*
	cp deps/* bindings/$*

c: ensure-c
	cd bindings/c && gcc -ludbserver example.c -o example && ./example

python: ensure-python
	swig -python -outdir bindings/python bindings/python/udbserver.i
	cd bindings/python && python3 setup.py build_ext --inplace && python3 example.py

go: ensure-go
	swig -go -intgosize 64 -outdir bindings/go bindings/go/udbserver.i
	GO111MODULE=on cd bindings/go && go run ./example
