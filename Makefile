.PHONY: test build install clean

ifeq ($(shell git status --porcelain),)
	VERSION = $(shell git describe --tags --abbrev=0)
endif

TEST_FORMAT ?= pkgname

define build
	@mkdir -p build
	$(eval OUTPUT := $(if $(filter windows,$(1)),aegis-$(1)-$(2).exe,aegis-$(1)-$(2)))
	$(eval URL := $(shell if [ -z "$(VERSION)" ]; then echo -n "" ; else echo -n https://github.com/malivvan/aegis/releases/download/$(VERSION)/$(OUTPUT); fi))
	$(eval SERIAL := $(shell if [ -z "$(VERSION)" ]; then uuidgen --random ; else uuidgen --sha1 --namespace @url --name $(URL); fi))
	@echo "$(OUTPUT)"
	@CGO_ENABLED=0 GOOS=$(1) GOARCH=$(2) go \
      build -trimpath -tags="$(4)" \
	  -ldflags="$(3) \
	  -buildid=$(SERIAL) \
	  -X main.version=$(VERSION)" \
	  -o build/$(OUTPUT) .
	@if [ ! -f build/RELEASE.md ]; then \
	  echo "| filename | serial |" > build/RELEASE.md; \
	  echo "|----------|--------|" >> build/RELEASE.md; \
	fi
	@if [ -z "$(VERSION)" ]; then \
	  echo "| $(OUTPUT) | $(SERIAL) |" >> build/RELEASE.md; \
	else \
	  echo "| [$(OUTPUT)]($(URL)) | [$(SERIAL)]($(URL).json) |" >> build/RELEASE.md; \
	fi
endef

install:
	@go install gotest.tools/gotestsum@latest

test:
	@CGO_ENABLED=0 gotestsum --format=$(TEST_FORMAT) --hide-summary skipped --format-hide-empty-pkg -- -short ./cli ./mhex ./kdbx ./mgrd/... ./opgp/...

build: clean
	$(call build,$(shell go env GOOS),$(shell go env GOARCH),,)

preview: clean
	$(call build,$(shell go env GOOS),$(shell go env GOARCH),-s -w,)

release: clean
	$(call build,linux,386,-s -w,)
	$(call build,linux,amd64,-s -w,)
	$(call build,linux,arm,-s -w,)
	$(call build,linux,arm64,-s -w,)
	$(call build,windows,amd64,-s -w,)
	$(call build,windows,386,-s -w,)
	$(call build,windows,arm,-s -w,)
	$(call build,windows,arm64,-s -w,)

clean:
	@rm -rf ./build