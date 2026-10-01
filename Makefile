# Usage:
#   make plan D=example.com        a domain
#   make plan D=account            account lists and bulk redirects
#   make help                      everything else
TF      ?= terraform
D       ?=
BACKEND := $(CURDIR)/backend.hcl

ifeq ($(D),account)
  DIR := account
  KEY := account.tfstate
else
  DIR := domains/$(D)
  KEY := domains/$(D).tfstate
endif

.PHONY: help check init plan apply test test-all fmt lint new export export-account domains

help:
	@echo "make new D=<domain> ZONE_ID=<id> PLAN=<free|pro|business|enterprise>  create from template"
	@echo "make export D=<domain> ZONE_ID=<id>     import an existing zone into YAML"
	@echo "make export-account ACCOUNT_ID=<id>     import account lists and bulk redirects"
	@echo "make test D=<domain|account>            offline checks, no token"
	@echo "make test-all                           offline checks for every root"
	@echo "make plan D=<domain|account>            plan against Cloudflare"
	@echo "make apply D=<domain|account>           apply the saved plan"
	@echo "make fmt | lint | domains"

check:
	@test -n "$(D)" || (echo "Set D=<domain> or D=account, e.g. make plan D=example.com" && exit 1)
	@test -d "$(DIR)" || (echo "No such folder: $(DIR)" && exit 1)

init: check
	@test -f "$(BACKEND)" || (echo "Missing backend.hcl: cp backend.hcl.example backend.hcl and fill it in" && exit 1)
	$(TF) -chdir=$(DIR) init -input=false -reconfigure \
	  -backend-config=$(BACKEND) -backend-config="key=$(KEY)"

plan: init
	$(TF) -chdir=$(DIR) plan -input=false -out=plan.bin

apply: check
	@test -f "$(DIR)/plan.bin" || (echo "Run make plan D=$(D) first" && exit 1)
	$(TF) -chdir=$(DIR) apply -input=false plan.bin
	@rm -f $(DIR)/plan.bin

# imports.tf is set aside during the offline test: mocked providers cannot
# import, and import blocks only matter for a real plan.
test: check
	@set -e; cd $(DIR); \
	if [ -f imports.tf ]; then mv imports.tf .imports.tf.skip; trap 'mv .imports.tf.skip imports.tf' EXIT; fi; \
	$(TF) init -backend=false -input=false >/dev/null; \
	$(TF) test

test-all:
	@set -e; for d in account $$(ls domains | grep -v '^_'); do \
	  echo "== $$d"; $(MAKE) --no-print-directory test D=$$d; done

fmt:
	$(TF) fmt -recursive

lint:
	$(TF) fmt -recursive -check
	yamllint -d relaxed domains account

domains:
	@ls domains | grep -v '^_'

new:
	@test -n "$(D)" -a -n "$(ZONE_ID)" -a -n "$(PLAN)" || (echo "make new D=example.org ZONE_ID=... PLAN=pro" && exit 1)
	./scripts/new-domain.sh $(D) $(ZONE_ID) $(PLAN)

export:
	@test -n "$(D)" -a -n "$(ZONE_ID)" || (echo "make export D=example.org ZONE_ID=..." && exit 1)
	python3 scripts/export_zone.py --zone-id $(ZONE_ID) --domain $(D)

export-account:
	@test -n "$(ACCOUNT_ID)" || (echo "make export-account ACCOUNT_ID=..." && exit 1)
	python3 scripts/export_zone.py --account-id $(ACCOUNT_ID)
