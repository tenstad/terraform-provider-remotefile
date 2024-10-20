CONTAINER_RUNTIME ?= $(shell command -v podman 2> /dev/null || echo docker)
DEVCONTAINER ?= $(shell if test -f /.dockerenv; then echo true; else echo false; fi)
# Attempts to find network of current container when DEVCONTAINER=true
CONTAINER_NETWORK ?= $(shell \
	if ( "$(DEVCONTAINER)" -eq "true" ); then \
		$(CONTAINER_RUNTIME) inspect $(shell cat /proc/self/cgroup | grep "::/docker/" | cut -d"/" -f3) | jq -r '.[0].NetworkSettings.Networks | keys | .[0]' \
	; else \
		echo remote \
	; fi)

.PHONY: test
default: test doc

# Start host containers used for playground and testing
hosts: clean
	$(CONTAINER_RUNTIME) network create $(CONTAINER_NETWORK) || true
	$(CONTAINER_RUNTIME) build -t remotehost tests
	$(CONTAINER_RUNTIME) run --rm -d --net $(CONTAINER_NETWORK) --name remotehost -p 8022:22 remotehost
	$(CONTAINER_RUNTIME) run --rm -d --net $(CONTAINER_NETWORK) --name remotehost2 -p 8023:22 remotehost

# Stop containers
clean:
	$(CONTAINER_RUNTIME) rm -f remotehost remotehost2 || true
ifeq ($(DEVCONTAINER),false)
	$(CONTAINER_RUNTIME) network rm $(CONTAINER_NETWORK) || true
endif

# Run acceptance tests
test: hosts
ifeq ($(DEVCONTAINER),true)
	./tests/test.sh
else
	$(CONTAINER_RUNTIME) run --rm --net remote -v ~/go:/go:z -v $(PWD):/provider:z --workdir /provider \
	-e "TF_LOG=INFO" -e "TF_ACC=1" -e "TF_ACC_TERRAFORM_VERSION=1.0.11" -e "TESTARGS=$(TESTARGS)" \
	docker.io/golang:1.22 bash tests/test.sh
endif

# Install provider in playground
INSTALL_DIR=playground
TARGET_ARCH=$(shell go env GOOS)_$(shell go env GOARCH)
PROVIDER_PATH=.terraform/providers/registry.terraform.io/tenstad/remote/99.0.0/$(TARGET_ARCH)
BIN_PATH=$(INSTALL_DIR)/$(PROVIDER_PATH)/terraform-provider-remote_v99.0.0
install:
	mkdir -p $(INSTALL_DIR)/$(PROVIDER_PATH)
	go build -ldflags="-s -w -X main.version=99.0.0" -o $(BIN_PATH)

doc:
	cd tools && go generate
