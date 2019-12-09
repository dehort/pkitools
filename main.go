package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
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
	writePrivateKey("private_key.pem", privateKey)

	/*
		cacertBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &privateKey.PublicKey, privateKey)
		if err != nil {
			log.Fatal("error generating cacert:", err)
			return
		}
		fmt.Println("cacertBytes:", cacertBytes)
		writePublicKey("public_key.pem", cacertBytes)
	*/

	var block *pem.Block
	block, _ = readPemFile("private_key.pem")
	readPrivateKey(block)

	block, _ = readPemFile("public_key.pem")
	readCertificate(block)
}

func readPemFile(fileName string) (*pem.Block, error) {
	data, err := ioutil.ReadFile(fileName)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	block, rest := pem.Decode(data)
	fmt.Println("block:", block)
	fmt.Println("rest:", rest)

	return block, nil
}

func readPrivateKey(block *pem.Block) error {
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		panic("failed to parse certificate: " + err.Error())
	}
	fmt.Println("privateKey:", privateKey)
	return nil
}

func readCertificate(block *pem.Block) error {
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		panic("failed to parse certificate: " + err.Error())
	}
	fmt.Println("cert:", cert)
	return nil
}

func writePrivateKey(fileName string, privateKey *rsa.PrivateKey) error {
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

	return nil
}

func writePublicKey(fileName string, certBytes []byte) error {
	publicKeyFile, err := os.Create(fileName)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	var pemPublicBlock = &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	}

	//fmt.Println("pemPublicBlock:", pemPublicBlock)

	err = pem.Encode(publicKeyFile, pemPublicBlock)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	publicKeyFile.Close()

	return nil
}
