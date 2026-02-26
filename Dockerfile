FROM alpine AS builder

WORKDIR /urunit

COPY Makefile .

COPY src src

RUN apk update && apk add build-base linux-headers

RUN make

FROM scratch
COPY --from=builder /urunit/dist/urunit_static /urunit
ENTRYPOINT ["/urunit"]
