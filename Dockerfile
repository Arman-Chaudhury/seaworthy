FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/seaworthy ./cmd/seaworthy

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/seaworthy /usr/local/bin/seaworthy
USER nonroot
ENTRYPOINT ["/usr/local/bin/seaworthy"]
CMD ["help"]
