.PHONY: go-mod-tidy
go-mod-tidy:
	go mod tidy

.PHONY: generate
generate:
	echo "no code generation is needed"

.PHONY: docker-generate
docker-generate:
	echo "no code generation is needed"

.PHONY: test
test:
	go test ./... --race -p 1 --coverprofile coverage.out '-gcflags=all=-N -l'

.PHONY: image-test
image-test:
	docker buildx build -f build/images/unit-test/Dockerfile -t ctlabels-go/unit-test . --load

.PHONY: docker-test
docker-test: image-test
	$(eval WORKDIR := /go/src/github.com/everoute/ctlabels-go)
	docker run --rm -iu 0:0 -w $(WORKDIR) -v $(CURDIR):$(WORKDIR) ctlabels-go/unit-test make test