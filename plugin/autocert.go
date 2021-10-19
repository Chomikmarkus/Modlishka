/**

    "Modlishka" Reverse Proxy.

    Copyright 2018 (C) Piotr Duszyński piotr[at]duszynski.eu. All rights reserved.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

    You should have received a copy of the Modlishka License along with this program.

**/

package plugin

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"math/big"
	"time"

	"github.com/drk1wi/Modlishka/config"
	"github.com/drk1wi/Modlishka/log"
)

// Paste your CA certificate and key in the following format
// Ref: https://github.com/drk1wi/Modlishka/wiki/Quickstart-tutorial

const CA_CERT = `-----BEGIN CERTIFICATE-----\nMIIFRDCCBCygAwIBAgISBIFXw8kJRdCp6UFdX4345odNMA0GCSqGSIb3DQEBCwUA\nMDIxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MQswCQYDVQQD\nEwJSMzAeFw0yMTEwMTgyMDA5MDBaFw0yMjAxMTYyMDA4NTlaMCkxJzAlBgNVBAMM\nHioudmVyby1maS1oZW5raWxvYXNpYWtrYWF0Lm5ldDCCASIwDQYJKoZIhvcNAQEB\nBQADggEPADCCAQoCggEBAMlft9Vz+E2bR40CxBljZLgi6OAmT75BJhQp8i/Gq8yk\ns1Ye1mSIiS0Nd2c4EcAec0ZQqcXrOsH4HiQyZh6qjtY40H2SQOvgz6eAcYr0cHtH\n6Eeeafym/g6CqTIj7vDpTKxUJwQahMxwfOc2AS8YUmZjxlPxCs+xR1CBzGrELxS3\nzsGdN+p8FHHVo9pX9RYvb9nqs93/XzepLr63dddEi5bfFHzGPgUalXg60V4bhnqH\n2Ib7UqdoB3HZrte34okC+kifUNQB+NFNjYo4dI0D9gWLzJN1CLg5Knb98vEKOmI7\nm1qGs2qNV62Ks6gjM/kG6JQF+WgmOGn9YBwpXOYCcs0CAwEAAaOCAlswggJXMA4G\nA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwDAYD\nVR0TAQH/BAIwADAdBgNVHQ4EFgQUmUuGUgqQmnoBWNmEmotTWmGG7mYwHwYDVR0j\nBBgwFoAUFC6zF7dYVsuuUAlA5h+vnYsUwsYwVQYIKwYBBQUHAQEESTBHMCEGCCsG\nAQUFBzABhhVodHRwOi8vcjMuby5sZW5jci5vcmcwIgYIKwYBBQUHMAKGFmh0dHA6\nLy9yMy5pLmxlbmNyLm9yZy8wKQYDVR0RBCIwIIIeKi52ZXJvLWZpLWhlbmtpbG9h\nc2lha2thYXQubmV0MEwGA1UdIARFMEMwCAYGZ4EMAQIBMDcGCysGAQQBgt8TAQEB\nMCgwJgYIKwYBBQUHAgEWGmh0dHA6Ly9jcHMubGV0c2VuY3J5cHQub3JnMIIBBgYK\nKwYBBAHWeQIEAgSB9wSB9ADyAHcA36Veq2iCTx9sre64X04+WurNohKkal6OOxLA\nIERcKnMAAAF8lTx4QQAABAMASDBGAiEAmj6btXzbTdTP3I/n+72/c1vKTctg/edF\na8Jdqj6g+TQCIQCJ2o1RhEIdc4Kl+ZJuHX1U2eFTXzv7NTlRhWZRpjdSnAB3ACl5\nvvCeOTkh8FZzn2Old+W+V32cYAr4+U1dJlwlXceEAAABfJU8eDUAAAQDAEgwRgIh\nANol9iO6MSKM83ZIWkKITD5KxsVoyrB/fABU7HmhyNzAAiEA2kW12z2JGzITeVqw\n2SC0bVrVt3+co/RtGGNBF31OTtMwDQYJKoZIhvcNAQELBQADggEBADU3EZzveIT/\n5vzNR3eQp9OyZoy2Wh4Xu0uYSjDPMFvP4tsm28f0egMuKVyHiNnYYZ+oyZHpj8e2\nUe1p6QW0eanUCvv3hnUDHrTSmOkxEAeFN6N5TzWcknV0gb3v+7c7tvgvJlv/cjUN\ntOKMQOi5MirvNPk/CNOGyXtvyp5x9aoBrHPNhXOrlahUqFC1iD+0ILrxyuitJ8Ij\nllDe43aKHxf+vxrBCemqn02pE0NEEpxE6qBZ+4ogHI6M8U/WMlZUfeqRUZc35rG1\nJ1GZ6K4NBu9RzjawbPJTYRbeU8teTrtCBF3cUKv+BaSFqDLJFmMIL3PywKCWVsg/\nz+ggZ7J/JW4=\n-----END CERTIFICATE-----\n
`

const CA_CERT_KEY = `-----BEGIN CERTIFICATE-----\nMIIFRDCCBCygAwIBAgISBIFXw8kJRdCp6UFdX4345odNMA0GCSqGSIb3DQEBCwUA\nMDIxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MQswCQYDVQQD\nEwJSMzAeFw0yMTEwMTgyMDA5MDBaFw0yMjAxMTYyMDA4NTlaMCkxJzAlBgNVBAMM\nHioudmVyby1maS1oZW5raWxvYXNpYWtrYWF0Lm5ldDCCASIwDQYJKoZIhvcNAQEB\nBQADggEPADCCAQoCggEBAMlft9Vz+E2bR40CxBljZLgi6OAmT75BJhQp8i/Gq8yk\ns1Ye1mSIiS0Nd2c4EcAec0ZQqcXrOsH4HiQyZh6qjtY40H2SQOvgz6eAcYr0cHtH\n6Eeeafym/g6CqTIj7vDpTKxUJwQahMxwfOc2AS8YUmZjxlPxCs+xR1CBzGrELxS3\nzsGdN+p8FHHVo9pX9RYvb9nqs93/XzepLr63dddEi5bfFHzGPgUalXg60V4bhnqH\n2Ib7UqdoB3HZrte34okC+kifUNQB+NFNjYo4dI0D9gWLzJN1CLg5Knb98vEKOmI7\nm1qGs2qNV62Ks6gjM/kG6JQF+WgmOGn9YBwpXOYCcs0CAwEAAaOCAlswggJXMA4G\nA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwDAYD\nVR0TAQH/BAIwADAdBgNVHQ4EFgQUmUuGUgqQmnoBWNmEmotTWmGG7mYwHwYDVR0j\nBBgwFoAUFC6zF7dYVsuuUAlA5h+vnYsUwsYwVQYIKwYBBQUHAQEESTBHMCEGCCsG\nAQUFBzABhhVodHRwOi8vcjMuby5sZW5jci5vcmcwIgYIKwYBBQUHMAKGFmh0dHA6\nLy9yMy5pLmxlbmNyLm9yZy8wKQYDVR0RBCIwIIIeKi52ZXJvLWZpLWhlbmtpbG9h\nc2lha2thYXQubmV0MEwGA1UdIARFMEMwCAYGZ4EMAQIBMDcGCysGAQQBgt8TAQEB\nMCgwJgYIKwYBBQUHAgEWGmh0dHA6Ly9jcHMubGV0c2VuY3J5cHQub3JnMIIBBgYK\nKwYBBAHWeQIEAgSB9wSB9ADyAHcA36Veq2iCTx9sre64X04+WurNohKkal6OOxLA\nIERcKnMAAAF8lTx4QQAABAMASDBGAiEAmj6btXzbTdTP3I/n+72/c1vKTctg/edF\na8Jdqj6g+TQCIQCJ2o1RhEIdc4Kl+ZJuHX1U2eFTXzv7NTlRhWZRpjdSnAB3ACl5\nvvCeOTkh8FZzn2Old+W+V32cYAr4+U1dJlwlXceEAAABfJU8eDUAAAQDAEgwRgIh\nANol9iO6MSKM83ZIWkKITD5KxsVoyrB/fABU7HmhyNzAAiEA2kW12z2JGzITeVqw\n2SC0bVrVt3+co/RtGGNBF31OTtMwDQYJKoZIhvcNAQELBQADggEBADU3EZzveIT/\n5vzNR3eQp9OyZoy2Wh4Xu0uYSjDPMFvP4tsm28f0egMuKVyHiNnYYZ+oyZHpj8e2\nUe1p6QW0eanUCvv3hnUDHrTSmOkxEAeFN6N5TzWcknV0gb3v+7c7tvgvJlv/cjUN\ntOKMQOi5MirvNPk/CNOGyXtvyp5x9aoBrHPNhXOrlahUqFC1iD+0ILrxyuitJ8Ij\nllDe43aKHxf+vxrBCemqn02pE0NEEpxE6qBZ+4ogHI6M8U/WMlZUfeqRUZc35rG1\nJ1GZ6K4NBu9RzjawbPJTYRbeU8teTrtCBF3cUKv+BaSFqDLJFmMIL3PywKCWVsg/\nz+ggZ7J/JW4=\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nMIIFFjCCAv6gAwIBAgIRAJErCErPDBinU/bWLiWnX1owDQYJKoZIhvcNAQELBQAw\nTzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh\ncmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMjAwOTA0MDAwMDAw\nWhcNMjUwOTE1MTYwMDAwWjAyMQswCQYDVQQGEwJVUzEWMBQGA1UEChMNTGV0J3Mg\nRW5jcnlwdDELMAkGA1UEAxMCUjMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK\nAoIBAQC7AhUozPaglNMPEuyNVZLD+ILxmaZ6QoinXSaqtSu5xUyxr45r+XXIo9cP\nR5QUVTVXjJ6oojkZ9YI8QqlObvU7wy7bjcCwXPNZOOftz2nwWgsbvsCUJCWH+jdx\nsxPnHKzhm+/b5DtFUkWWqcFTzjTIUu61ru2P3mBw4qVUq7ZtDpelQDRrK9O8Zutm\nNHz6a4uPVymZ+DAXXbpyb/uBxa3Shlg9F8fnCbvxK/eG3MHacV3URuPMrSXBiLxg\nZ3Vms/EY96Jc5lP/Ooi2R6X/ExjqmAl3P51T+c8B5fWmcBcUr2Ok/5mzk53cU6cG\n/kiFHaFpriV1uxPMUgP17VGhi9sVAgMBAAGjggEIMIIBBDAOBgNVHQ8BAf8EBAMC\nAYYwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMBMBIGA1UdEwEB/wQIMAYB\nAf8CAQAwHQYDVR0OBBYEFBQusxe3WFbLrlAJQOYfr52LFMLGMB8GA1UdIwQYMBaA\nFHm0WeZ7tuXkAXOACIjIGlj26ZtuMDIGCCsGAQUFBwEBBCYwJDAiBggrBgEFBQcw\nAoYWaHR0cDovL3gxLmkubGVuY3Iub3JnLzAnBgNVHR8EIDAeMBygGqAYhhZodHRw\nOi8veDEuYy5sZW5jci5vcmcvMCIGA1UdIAQbMBkwCAYGZ4EMAQIBMA0GCysGAQQB\ngt8TAQEBMA0GCSqGSIb3DQEBCwUAA4ICAQCFyk5HPqP3hUSFvNVneLKYY611TR6W\nPTNlclQtgaDqw+34IL9fzLdwALduO/ZelN7kIJ+m74uyA+eitRY8kc607TkC53wl\nikfmZW4/RvTZ8M6UK+5UzhK8jCdLuMGYL6KvzXGRSgi3yLgjewQtCPkIVz6D2QQz\nCkcheAmCJ8MqyJu5zlzyZMjAvnnAT45tRAxekrsu94sQ4egdRCnbWSDtY7kh+BIm\nlJNXoB1lBMEKIq4QDUOXoRgffuDghje1WrG9ML+Hbisq/yFOGwXD9RiX8F6sw6W4\navAuvDszue5L3sz85K+EC4Y/wFVDNvZo4TYXao6Z0f+lQKc0t8DQYzk1OXVu8rp2\nyJMC6alLbBfODALZvYH7n7do1AZls4I9d1P4jnkDrQoxB3UqQ9hVl3LEKQ73xF1O\nyK5GhDDX8oVfGKF5u+decIsH4YaTw7mP3GFxJSqv3+0lUFJoi5Lc5da149p90Ids\nhCExroL1+7mryIkXPeFM5TgO9r0rvZaBFOvV2z0gp35Z0+L4WPlbuEjN/lxPFin+\nHlUjr8gRsI3qfJOQFy/9rKIJR0Y/8Omwt/8oTWgy1mdeHmmjk7j1nYsvC9JSQ6Zv\nMldlTTKB3zhThV1+XWYp6rjd5JW1zbVWEkLNxE7GJThEUG3szgBVGP7pSWTUTsqX\nnLRbwHOoq7hHwg==\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nMIIFYDCCBEigAwIBAgIQQAF3ITfU6UK47naqPGQKtzANBgkqhkiG9w0BAQsFADA/\nMSQwIgYDVQQKExtEaWdpdGFsIFNpZ25hdHVyZSBUcnVzdCBDby4xFzAVBgNVBAMT\nDkRTVCBSb290IENBIFgzMB4XDTIxMDEyMDE5MTQwM1oXDTI0MDkzMDE4MTQwM1ow\nTzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh\ncmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwggIiMA0GCSqGSIb3DQEB\nAQUAA4ICDwAwggIKAoICAQCt6CRz9BQ385ueK1coHIe+3LffOJCMbjzmV6B493XC\nov71am72AE8o295ohmxEk7axY/0UEmu/H9LqMZshftEzPLpI9d1537O4/xLxIZpL\nwYqGcWlKZmZsj348cL+tKSIG8+TA5oCu4kuPt5l+lAOf00eXfJlII1PoOK5PCm+D\nLtFJV4yAdLbaL9A4jXsDcCEbdfIwPPqPrt3aY6vrFk/CjhFLfs8L6P+1dy70sntK\n4EwSJQxwjQMpoOFTJOwT2e4ZvxCzSow/iaNhUd6shweU9GNx7C7ib1uYgeGJXDR5\nbHbvO5BieebbpJovJsXQEOEO3tkQjhb7t/eo98flAgeYjzYIlefiN5YNNnWe+w5y\nsR2bvAP5SQXYgd0FtCrWQemsAXaVCg/Y39W9Eh81LygXbNKYwagJZHduRze6zqxZ\nXmidf3LWicUGQSk+WT7dJvUkyRGnWqNMQB9GoZm1pzpRboY7nn1ypxIFeFntPlF4\nFQsDj43QLwWyPntKHEtzBRL8xurgUBN8Q5N0s8p0544fAQjQMNRbcTa0B7rBMDBc\nSLeCO5imfWCKoqMpgsy6vYMEG6KDA0Gh1gXxG8K28Kh8hjtGqEgqiNx2mna/H2ql\nPRmP6zjzZN7IKw0KKP/32+IVQtQi0Cdd4Xn+GOdwiK1O5tmLOsbdJ1Fu/7xk9TND\nTwIDAQABo4IBRjCCAUIwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYw\nSwYIKwYBBQUHAQEEPzA9MDsGCCsGAQUFBzAChi9odHRwOi8vYXBwcy5pZGVudHJ1\nc3QuY29tL3Jvb3RzL2RzdHJvb3RjYXgzLnA3YzAfBgNVHSMEGDAWgBTEp7Gkeyxx\n+tvhS5B1/8QVYIWJEDBUBgNVHSAETTBLMAgGBmeBDAECATA/BgsrBgEEAYLfEwEB\nATAwMC4GCCsGAQUFBwIBFiJodHRwOi8vY3BzLnJvb3QteDEubGV0c2VuY3J5cHQu\nb3JnMDwGA1UdHwQ1MDMwMaAvoC2GK2h0dHA6Ly9jcmwuaWRlbnRydXN0LmNvbS9E\nU1RST09UQ0FYM0NSTC5jcmwwHQYDVR0OBBYEFHm0WeZ7tuXkAXOACIjIGlj26Ztu\nMA0GCSqGSIb3DQEBCwUAA4IBAQAKcwBslm7/DlLQrt2M51oGrS+o44+/yQoDFVDC\n5WxCu2+b9LRPwkSICHXM6webFGJueN7sJ7o5XPWioW5WlHAQU7G75K/QosMrAdSW\n9MUgNTP52GE24HGNtLi1qoJFlcDyqSMo59ahy2cI2qBDLKobkx/J3vWraV0T9VuG\nWCLKTVXkcGdtwlfFRjlBz4pYg1htmf5X6DYO8A4jqv2Il9DjXA6USbW1FzXSLr9O\nhe8Y4IWS6wY7bCkjCWDcRQJMEhg76fsO3txE+FiYruq9RUWhiF1myv4Q6W+CyBFC\nDfvp7OOGAN6dEOM4+qR9sdjoSYKEBpsr6GtPAQw4dy753ec5\n-----END CERTIFICATE-----\n
`

func init() {

	s := Property{}

	s.Name = "autocert"
	s.Version = "0.1"
	s.Description = "This plugin is used to auto generate certificate for you . Really useful for testing different configuration flags against your targets. "

	s.Flags = func() {

		if *config.C.ForceHTTP == false {
			if len(*config.C.TLSCertificate) == 0 && len(*config.C.TLSKey) == 0 {

				log.Infof("Autocert plugin: Auto-generating %s domain TLS certificate",*config.C.ProxyDomain)

				CAcert := CA_CERT
				CAkey := CA_CERT_KEY

				catls, err := tls.X509KeyPair([]byte(CAcert), []byte(CAkey))
				if err != nil {
					panic(err)
				}
				ca, err := x509.ParseCertificate(catls.Certificate[0])
				if err != nil {
					panic(err)
				}

				var n int32
				binary.Read(rand.Reader, binary.LittleEndian, &n)

				template := &x509.Certificate{
					IsCA:                  false,
					BasicConstraintsValid: true,
					SubjectKeyId:          []byte{1, 2, 3},
					SerialNumber:          big.NewInt(int64(n)),
					DNSNames:              []string{*config.C.ProxyDomain, "*." + *config.C.ProxyDomain},
					Subject: pkix.Name{
						Country:      []string{"Earth"},
						Organization: []string{"Mother Nature"},
						CommonName:   *config.C.ProxyDomain,
					},
					NotBefore: time.Now(),
					NotAfter:  time.Now().AddDate(5, 5, 5),
				}

				// generate private key
				privatekey, err := rsa.GenerateKey(rand.Reader, 2048)

				if err != nil {
					log.Errorf("Error generating key: %s", err)
				}
				var privateKey = &pem.Block{
					Type:  "PRIVATE KEY",
					Bytes: x509.MarshalPKCS1PrivateKey(privatekey),
				}

				//dump
				buf := new(bytes.Buffer)
				pem.Encode(buf, privateKey)
				tlskeyStr := buf.String()
				config.C.TLSKey = &tlskeyStr
				log.Debugf("AutoCert plugin generated TlsKey:\n %s", *config.C.TLSKey)

				// generate self signed cert
				publickey := &privatekey.PublicKey

				// create a self-signed certificate. template = parent
				//var parent = template
				var parent = ca

				cert, err := x509.CreateCertificate(rand.Reader, template, parent, publickey, catls.PrivateKey)

				buf = new(bytes.Buffer)
				pem.Encode(buf, &pem.Block{Type: "CERTIFICATE", Bytes: cert})

				tlscertStr := buf.String()
				config.C.TLSCertificate = &tlscertStr
				log.Debugf("AutoCert plugin generated TlsCert:\n %s", *config.C.TLSCertificate)

				//the cert is auto-generated anyway
				*config.C.TLSPool = ""

				if err != nil {
					log.Errorf("Error creating certificate: %s", err)
				}

			}
		}

	}

	// Register all the function hooks
	s.Register()
}
