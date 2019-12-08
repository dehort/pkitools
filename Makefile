
.PHONY: myca

myca:
	go run main.go

verify:
	openssl x509 -noout -modulus -in public_key.pem | openssl md5
	openssl rsa -noout -modulus -in private_key.pem | openssl md5

fmt:
	go fmt ./...
