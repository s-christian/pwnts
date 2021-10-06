# Pwnts Notes

## Generating a certificate for TLS use

```go
cd <pwnts_dir>
go run "C:/Program Files/Go/src/crypto/tls/generate_cert.go" --host="pwnts.red,localhost"
```

Name the certificate `pwnts.red.pem` and the private key `pwnts_server_key.pem`.