.PHONY: test
test:
	go test ./... --race -p 1 --coverprofile coverage.out '-gcflags=all=-N -l'

.PHONY: go-mod-tidy
go-mod-tidy:
	go mod tidy
