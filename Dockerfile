FROM alpine AS builder

WORKDIR /urunit

COPY Makefile .

COPY src src

COPY tests tests

RUN apk update && apk add build-base linux-headers

RUN make test && make

FROM scratch
COPY --from=builder /urunit/dist/urunit_static /urunit
ENTRYPOINT ["/urunit"]
