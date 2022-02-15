.PHONY: rust c java python go

rust:
	cargo build --release

c:
	cd bindings/c && gcc -I../../include -L../../target/release example.c -lunicorn -ludbserver -o example && LD_LIBRARY_PATH=../../target/release ./example

java:
	cd bindings/java && make all && LD_LIBRARY_PATH=.:../../target/release make example

python:
	cd bindings/python && python3 setup.py build_ext --inplace && LD_LIBRARY_PATH=../../target/release python3 example.py

go:
	cd bindings/go && LD_LIBRARY_PATH=../../target/release go run ./example
