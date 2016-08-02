package main

import (
    "log"
    "crypto/tls"
    "fmt"
    "encoding/pem"
    "crypto/x509"
    //"os"
)

const pemString = `-----BEGIN CERTIFICATE-----
MIICYzCCAcwCCQDeIJ+k5a1tSDANBgkqhkiG9w0BAQUFADB2MQswCQYDVQQGEwJO
TDEVMBMGA1UECAwMWnVpZCBIb2xsYW5kMREwDwYDVQQHDAhEZW4gSGFhZzEWMBQG
A1UECgwNTWFpYXN0cmEgQi5WLjERMA8GA1UECwwIcmVzZWFyY2gxEjAQBgNVBAMM
CWNoZXdiYWNjYTAeFw0xNjA2MDkxMTI5NTBaFw0xNzA2MDkxMTI5NTBaMHYxCzAJ
BgNVBAYTAk5MMRUwEwYDVQQIDAxadWlkIEhvbGxhbmQxETAPBgNVBAcMCERlbiBI
YWFnMRYwFAYDVQQKDA1NYWlhc3RyYSBCLlYuMREwDwYDVQQLDAhyZXNlYXJjaDES
MBAGA1UEAwwJY2hld2JhY2NhMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDB
15zaRtWfDyqDB6OvxX7IW8rrV034EQeiqzcsfEm3q/Edfy56uswUJIKQ8xK8Utn8
KVmseYbdTpFnCHJKg1vPldlmr6X82wq+FYBS8o5QT3zQHlENUMHe5BntbvKRxpt6
CIWps5Wpk3HBSsfwIMhpK9BVISyLsf023qh+kGLCXQIDAQABMA0GCSqGSIb3DQEB
BQUAA4GBAF8DklVl8yRQB7070TDCv3z28HdmCn9thXhyY22Sl3CROc2jP5L3y8ge
kzF+ZIzUAhrjeYc8xXPA56ZEASLgSKYN1KiTI4W+jXkVKFBgvh1LoPn914iZBiCJ
3/aSSPKbcfOqSBKLENPUtP0XDlA9e05apVhkDjQDHIAkxvlcAx0F
-----END CERTIFICATE-----`

func main() {
    log.SetFlags(log.Lshortfile)

    conf := &tls.Config{
        InsecureSkipVerify: true,
        
    }

    //conn, err := tls.Dial("tcp", "127.0.0.1:8000", conf)
    //conn, err := tls.Dial("tcp", "eng-hub.blackducksoftware.com:443", conf)
    //conn, err := tls.Dial("tcp", "updates.suite.blackducksoftware.com:443", conf)
    conn, err := tls.Dial("tcp", "192.168.2.16:8443", conf)
    if err != nil {
        log.Println(err)
        return
    }
    defer conn.Close()
    
    certificates := conn.ConnectionState().PeerCertificates
    for i, cert := range certificates {
    	fmt.Printf("%-5d cert : \n%v\n\n", i, cert.Raw)
    	str := string(cert.RawTBSCertificate[:])
    	fmt.Printf("to string : \n%s\n\n", str)
    	//fmt.Printf("RawTBSCertificate : \n%s\n\n", cert.RawTBSCertificate)
    	fmt.Printf("%v\n\n",   cert.PublicKeyAlgorithm)
    	fmt.Printf("Ext : \n%v\n\n",  cert.Extensions)
    	
//    	pemBlock, _ := pem.Decode([]byte(cert.RawTBSCertificate))
//    	cert.
//    	
//    	fmt.Printf("pemBlock : \n%v\n", pemBlock)
    	
    	//pem.Encode(os.Stdout, []byte(cert)) 
    	if cert.IsCA {
    		fmt.Println("signed certificate")
    	}else{
    		fmt.Println("Self signed certificate")
    		fmt.Printf("Common Name : %s\n", cert.Subject.CommonName)
    	}
    	fmt.Printf("Raw subject : %v\n\n", cert.RawSubject)
    	fmt.Printf("Certificate subject : %v\n\n", cert.Subject)
    	fmt.Printf("Certificate issuer  : %v\n\n", cert.Issuer)
    	   	
    	
    }
    
    
    pBlock, _ := pem.Decode([]byte(pemString))
    
    cert, err := x509.ParseCertificate(pBlock.Bytes)
    
    if err != nil {
    	panic("failed to parse certificate: " + err.Error())
    }
    
    fmt.Printf("cert : \n%v\n\n", cert)
    
    fmt.Printf("prr : \n%v\n\n", conn.ConnectionState().ServerName)
    
   

//    n, err := conn.Write([]byte("hello\n"))
//    if err != nil {
//        log.Println(n, err)
//        return
//    }
//
//    buf := make([]byte, 100)
//    n, err = conn.Read(buf)
//    if err != nil {
//        log.Println(n, err)
//        return
//    }
//
//    println(string(buf[:n]))
}

