package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"net"
	"os"
	"time"
)

func main() {
	// get our ca and server certificate
	//serverTLSConf, clientTLSConf, err := certsetup()
	_, _, err := certsetup()
	if err != nil {
		panic(err)
	}

	// // set up the httptest.Server using our certificate signed by our CA
	// server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	// 	fmt.Fprintln(w, "success!")
	// }))
	// server.TLS = serverTLSConf
	// server.StartTLS()
	// defer server.Close()

	// communicate with the server using an http.Client configured to trust our CA
	// transport := &http.Transport{
	// 	TLSClientConfig: clientTLSConf,
	// }
	// http := http.Client{
	// 	Transport: transport,
	// }
	// resp, err := http.Get(server.URL)
	// if err != nil {
	// 	panic(err)
	// }

	// verify the response
	// respBodyBytes, err := ioutil.ReadAll(resp.Body)
	// if err != nil {
	// 	panic(err)
	// }
	// body := strings.TrimSpace(string(respBodyBytes[:]))
	// if body == "success!" {
	// 	fmt.Println(body)
	// } else {
	// 	panic("not successful!")
	// }
}

func certsetup() (serverTLSConf *tls.Config, clientTLSConf *tls.Config, err error) {
	//func certsetup() (caPrivKey *tls.Config, caPublicKey *tls.Config, caPEM *tls.Config, err error) {
	// set up our CA certificate
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(2019), // ml-TODO: gen new
		Subject: pkix.Name{
			Organization:  []string{"Company, INC."},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"San Francisco"},
			StreetAddress: []string{"Golden Gate Bridge"},
			PostalCode:    []string{"94016"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	// create our private and public key
	caPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, err
	}

	// create the CA
	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return nil, nil, err
	}

	// write out ca public cert (caBytes)
	caPublicOut, err := os.Create("ca.crt")
	if err != nil {
		log.Fatalf("Failed to open ca.crt for writing: %v", err)
	}
	if err := pem.Encode(caPublicOut, &pem.Block{Type: "CERTIFICATE", Bytes: caBytes}); err != nil {
		log.Fatalf("Failed to write data to ca.crt: %v", err)
	}
	if err := caPublicOut.Close(); err != nil {
		log.Fatalf("Error closing ca.crt: %v", err)
	}

	// pem encode
	caPEM := new(bytes.Buffer)
	pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})

	caPrivKeyPEM := new(bytes.Buffer)
	pem.Encode(caPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(caPrivKey),
	})

	// write out ca private (caPrivKeyPEM)
	caPrivateOut, err := os.OpenFile("ca.key", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Fatalf("Failed to open ca.key for writing: %v", err)
		return
	}
	pem.Encode(caPrivateOut, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(caPrivKey),
	})
	if err := caPrivateOut.Close(); err != nil {
		log.Fatalf("Error closing ca.key: %v", err)
	}

	// set up our server certificate
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			Organization:  []string{"Company, INC."},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"San Francisco"},
			StreetAddress: []string{"Golden Gate Bridge"},
			PostalCode:    []string{"94016"},
		},
		// kubectl get nodes -A -o jsonpath='{.items[*].status.addresses[?(@.type=="InternalIP")].address}' = 192.168.10.19 192.168.10.10 192.168.10.11 192.168.10.12
		// kubectl get nodes -A -o jsonpath='{.items[*].status.addresses[?(@.type=="Hostname")].address}' = mudassir-k8s-1-master mudassir-k8s-1-node0 mudassir-k8s-1-node1 mudassir-k8s-1-node2
		// kubectl get nodes -A -o jsonpath='{.items[*].metadata.annotations}' | jq -r . | grep public-ip =  "192.168.121.105", "192.168.121.178", "192.168.121.6", "192.168.121.28",
		DNSNames: []string{"portworx-api.kube-system", "portworx-service.kube-system", "mudassir-k8s-1-master", "mudassir-k8s-1-node0", "mudassir-k8s-1-node1", "mudassir-k8s-1-node2"},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback,
			net.IPv4(192, 168, 10, 19), net.IPv4(192, 168, 10, 10), net.IPv4(192, 168, 10, 11), net.IPv4(192, 168, 10, 12),
			net.IPv4(192, 168, 121, 105), net.IPv4(192, 168, 121, 178), net.IPv4(192, 168, 121, 6), net.IPv4(192, 168, 121, 28),
		},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	certPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, err
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, cert, ca, &certPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return nil, nil, err
	}

	certPEM := new(bytes.Buffer)
	pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	// write out server cert (certBytes)
	serverCertOut, err := os.OpenFile("server.crt", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Fatalf("Failed to open server.crt for writing: %v", err)
		return
	}
	pem.Encode(serverCertOut, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})
	if err := serverCertOut.Close(); err != nil {
		log.Fatalf("Error closing server.crt: %v", err)
	}

	certPrivKeyPEM := new(bytes.Buffer)
	pem.Encode(certPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(certPrivKey),
	})

	// write out server key (certPrivKey)
	serverKeyOut, err := os.OpenFile("server.key", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Fatalf("Failed to open server.key for writing: %v", err)
		return
	}
	pem.Encode(serverKeyOut, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(certPrivKey),
	})
	if err := serverKeyOut.Close(); err != nil {
		log.Fatalf("Error closing server.key: %v", err)
	}

	serverCert, err := tls.X509KeyPair(certPEM.Bytes(), certPrivKeyPEM.Bytes())
	if err != nil {
		return nil, nil, err
	}

	serverTLSConf = &tls.Config{
		Certificates: []tls.Certificate{serverCert},
	}

	certpool := x509.NewCertPool()
	certpool.AppendCertsFromPEM(caPEM.Bytes())
	clientTLSConf = &tls.Config{
		RootCAs: certpool,
	}

	return
}
