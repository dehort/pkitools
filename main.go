package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"os"
	"time"
)

func main() {
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(1653),
		Subject: pkix.Name{
			Organization:  []string{"my org"},
			Country:       []string{"my country"},
			Province:      []string{"my province"},
			Locality:      []string{"my city"},
			StreetAddress: []string{"my address"},
			PostalCode:    []string{"my postal code"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(0, 1, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	fmt.Println("ca cert:", ca)

	// rand.Reader reads from /dev/urandom...get random bytes for key generation
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)

	if err != nil {
		log.Fatalf("error generating key")
		return
	}
	fmt.Println("privateKey:", privateKey)
	fmt.Println("err:", err)

	cacertBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &privateKey.PublicKey, privateKey)
	if err != nil {
		log.Fatal("error generating cacert:", err)
		return
	}
	fmt.Println("cacertBytes:", cacertBytes)
	//func CreateCertificate(rand io.Reader, template, parent *Certificate, pub, priv interface{}) (cert []byte, err error)

	pemPrivateFile, err := os.Create("private_key.pem")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	var pemPrivateBlock = &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}

	fmt.Println("pemPrivateBlock:", pemPrivateBlock)

	err = pem.Encode(pemPrivateFile, pemPrivateBlock)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	pemPrivateFile.Close()
	// ---------------------------------------------

	// ---------------------------------------------
	// Public Key
	pemPublicFile, err := os.Create("public_key.pem")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	var pemPublicBlock = &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cacertBytes,
	}

	fmt.Println("pemPublicBlock:", pemPublicBlock)

	err = pem.Encode(pemPublicFile, pemPublicBlock)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	pemPublicFile.Close()
	// ---------------------------------------------

}
