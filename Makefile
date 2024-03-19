
.PHONY: build
build:
	@cargo make build

.PHONY: clean
clean:
	@cargo make clean

.PHONY: test
test:
	@cargo make test

.PHONY: doc
doc:
	@cargo doc --no-deps

.PHONY: fmt
fmt:
	cargo make fmt

.PHONY: lint
lint:
	@cargo make lint

.PHONY: audit
audit: 
	@cargo make audit

.PHONY: unused
unused:
	@cargo make unused

.PHONY: check
check:
	@cargo make check

.PHONY: breaking
breaking:
	# cargo install cargo-semver-checks --locked
	@cargo semver-checks

.PHONY: pub-check
pub-check:
	@cargo publish --dry-run --package vercre-core
	@cargo publish --dry-run --package vercre-vci
	@cargo publish --dry-run --package vercre-vp
	@cargo publish --dry-run --package vercre-wallet

# test-doc:
# 	@cargo test --doc -- --nocapture --color=always

# test-miri:
# 	MIRIFLAGS="-Zmiri-disable-isolation -Zmiri-panic-on-unsupported" cargo miri test -- --nocapture --color=always
# 	# @cargo miri nextest run -J20