.PHONY: all vendor

all: build

build:
	cargo test --offline
	cargo build --release --locked --offline

vendor:
	cargo vendor

clean:
	rm -rf target
