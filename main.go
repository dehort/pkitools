package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	//"errors"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"time"
)

func main() {

	subject := pkix.Name{
		Organization: []string{"my org"},
		Country:      []string{"my country"},
		Locality:     []string{"my city"},
	}

	subject.CommonName = "root"
	caPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("error generating key: %s", err)
	}
	caCert, err := createCert(subject.CommonName, subject, nil, &caPrivateKey.PublicKey, caPrivateKey)
	if err != nil {
		log.Fatalf("error generating key: %s", err)
	}
	writePrivateKey(fmt.Sprintf("%s_key.pem", subject.CommonName), caPrivateKey)
	//writeCertificate(fmt.Sprintf("%s_cert.pem", subject.CommonName), caCert)

	subject.CommonName = "intermediate"
	interCaPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("error generating key")
	}
	interCert, err := createCert(subject.CommonName, subject, caCert, &interCaPrivateKey.PublicKey, caPrivateKey)
	writePrivateKey(fmt.Sprintf("%s_key.pem", subject.CommonName), interCaPrivateKey)
	//writeCertificate(fmt.Sprintf("%s_cert.pem", subject.CommonName), interCert)
	fmt.Println(interCert, err)

	subject.CommonName = "server"
	serverPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("error generating key")
	}
	serverCert, err := createCert(subject.CommonName, subject, interCert, &serverPrivateKey.PublicKey, interCaPrivateKey)
	writePrivateKey(fmt.Sprintf("%s_key.pem", subject.CommonName), serverPrivateKey)
	fmt.Println(serverCert, err)

	//createCert("server", subject)

	/*
		generateCSR(privateKey)
	*/

	/*
		var block *pem.Block
		block, _ = readPemFile("private_key.pem")
		readPrivateKey(block)

		block, _ = readPemFile("public_key.pem")
		readCertificate(block)
	*/
}

func createCert(name string, subject pkix.Name, parentCert *x509.Certificate, pubKey interface{}, privKey interface{}) (*x509.Certificate, error) {
	ca := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               subject,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(0, 1, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	if parentCert == nil {
		parentCert = ca
	}

	fmt.Println("ca cert:", ca)

	//fmt.Println("privateKey:", privateKey)
	//writePrivateKey(fmt.Sprintf("%s_key.pem", name), privateKey)

	cacertBytes, err := x509.CreateCertificate(rand.Reader, ca, parentCert, pubKey, privKey)
	if err != nil {
		log.Fatal("error generating cacert:", err)
		return nil, err
	}
	fmt.Println("cacertBytes:", cacertBytes)
	writePublicKey(fmt.Sprintf("%s_cert.pem", name), cacertBytes)

	cert, err := x509.ParseCertificate(cacertBytes)
	if err != nil {
		log.Fatal("error building cert object:", err)
		return nil, err
	}

	return cert, nil
}

func generateCSR(privateKey *rsa.PrivateKey) {
	csrTemplate := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "myserver"},
		DNSNames: []string{"myserver", "fred.flintstone.com"},
		//NotBefore:             time.Now(),
		//NotAfter:              time.Now().AddDate(0, 1, 0),
		//IsCA:                  true,
		//ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		//KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		//BasicConstraintsValid: true,

		//PublicKey: privateKey.PublicKey,
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, privateKey)
	fmt.Println("csrBytes:", csrBytes)
	fmt.Println("err:", err)

	writeCSR("csr.pem", csrBytes)
}

func writeCSR(fileName string, csrBytes []byte) error {
	csrFile, err := os.Create(fileName)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	var pemCSRBlock = &pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrBytes,
	}

	//fmt.Println("pemPublicBlock:", pemPublicBlock)

	err = pem.Encode(csrFile, pemCSRBlock)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	csrFile.Close()

	return nil
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
	pemPrivateFile, err := os.Create(fileName)
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

func writeCertificate(fileName string, cert *x509.Certificate) error {
	certBytes, err := x509.MarshalPKIXPublicKey(cert)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	return writePublicKey(fileName, certBytes)
}
