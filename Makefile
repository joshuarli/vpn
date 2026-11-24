.PHONY: test lint clean

test:
	cargo xtask test

lint:
	cargo clippy --locked --all-targets

clean:
	@if test -L ./target || { test -e ./target && ! test -d ./target; }; then \
	  printf '%s\n' 'make clean: ./target must be a local build directory' >&2; exit 1; \
	fi
	rm -rf -- ./target
