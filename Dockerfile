FROM golang:1.24 as builder

WORKDIR /workspace

COPY go.mod go.sum ./

RUN go mod download

COPY . .

RUN go build -o infrasight_sentinel cmd/main.go

FROM golang:bookworm

WORKDIR /workspace

COPY --from=builder /workspace/infrasight_sentinel .

ENTRYPOINT ["./infrasight_sentinel"]
