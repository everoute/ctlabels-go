FROM registry.smtx.io/sdn-base/golang:1.25 AS golang

ENV GOPROXY="http://goproxy.smartx.com|https://proxy.golang.org|direct"

ARG GO_MOD_PATH=/go/pkg/mod

# set PATH
ENV PATH=${PATH}:/usr/local/go/bin

WORKDIR /go/src/github.com/everoute/ctlabels-go/

COPY go.mod go.sum ./

RUN go mod download && go mod verify

COPY build/images/unit-test/docker-entrypoint.sh /
RUN chmod +x /docker-entrypoint.sh

ENTRYPOINT ["/docker-entrypoint.sh"]