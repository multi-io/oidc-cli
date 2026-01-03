.PHONY: build test namespace deploy

APPNAME=oidc-cli
GITTAG=$(shell git describe --tags --always $$(git log --format=format:%H -1 -- server *.go))  # latest commit that changed anything in server/ *.go

build:
	CGO_ENABLED=0 go build

test: build
	go test ./...

docker-build: go.mod go.sum *.go server Dockerfile
	docker build --platform linux/amd64 -t oklischat/$(APPNAME):$(GITTAG) .
	touch $@

docker-push: docker-build
	docker push oklischat/$(APPNAME):$(GITTAG)
	touch $@

namespace:
	kubectl create namespace $(APPNAME) --dry-run=client -o yaml | kubectl apply -f -

deploy: docker-push namespace
	kubectl kustomize ./ | sed 's/APPNAME/$(APPNAME)/' | sed 's/GITTAG/$(GITTAG)/' | kubectl apply --prune -l app=$(APPNAME) -f -

undeploy:
	kubectl kustomize ./ | sed 's/APPNAME/$(APPNAME)/' | sed 's/GITTAG/$(GITTAG)/' | kubectl delete -f -
