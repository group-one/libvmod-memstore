.PHONY: all vendor

all: build

build:
	cargo build
	cargo test
	cargo build --release --locked

vendor:
	cargo vendor

clean:
	rm -rf target
