package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"os"
	"strings"
	"time"
)

func main() {
	// パラメタチェック
	num := len(os.Args)
	if num != 2 {
		log.Fatal("Specify Hostname for cert check")
	}
	host := os.Args[1]
	//	fmt.Println(host)

	// TLS接続
	config := tls.Config{}
	conn, err := tls.Dial("tcp", host+":443", &config)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	state := conn.ConnectionState()
	var certs []*x509.Certificate
	for _, v := range state.PeerCertificates {
		certs = append(certs, v)
	}

	//
	certInfo, err := checkCertificate(host, certs)
	fmt.Printf("%s", certInfo.string())
}

const (
	DV = iota
	OV
	EV
)

type certInfo struct {
	certIssuer string
	certCN     string
	certBegin  time.Time
	certEnd    time.Time
	certType   int
}

func (c certInfo) string() string {
	var ct string
	switch c.certType {
	case DV:
		ct = "DV"
	case OV:
		ct = "OV"
	case EV:
		ct = "EV"
	default:
		ct = "unknown"
	}

	output := `Issuer : %s
CommonName : %s
Period : %s - %s
Type : %s
`

	return fmt.Sprintf(output, c.certIssuer, c.certCN, c.certBegin.Format("2006/01/02 15:04:05"), c.certEnd.Format("2006/01/02 15:04:05"), ct)
}

func checkCertificate(host string, certs []*x509.Certificate) (certInfo, error) {
	ci := certInfo{}
	found := false
	for _, cert := range certs {
		if host == cert.Subject.CommonName {
			found = true
		} else {
			for _, name := range cert.DNSNames {
				if name == cert.Subject.CommonName {
					found = true
				}
			}
		}

		if found {
			ci.certBegin = cert.NotBefore
			ci.certEnd = cert.NotAfter
			ci.certType = checkCertType(cert)
			ci.certCN = cert.Subject.CommonName
			ci.certIssuer = cert.Issuer.CommonName
			break
		}
	}

	return ci, nil
}

func checkCertType(cert *x509.Certificate) int {
	certType := DV
	if cert.Subject.Organization != nil {
		certType = OV
		issuer := cert.Issuer.CommonName
		if strings.Contains(issuer, "Extend") || strings.Contains(issuer, "EV") {
			certType = EV
		}
	}
	return certType
}
