/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package util

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	cos "intel/isecl/lib/common/os"
	"intel/isecl/lib/common/crypt"
	flvr "intel/isecl/lib/flavor"

	log "github.com/sirupsen/logrus"

)


func verifyFlavorSignatureWithCertChainVerification(flavor flvr.SignedImageFlavor, certPemSlice, rootCAPems [][]byte) bool{
	// build the trust root CAs first
	var imageFlavor flvr.ImageFlavor
	roots := x509.NewCertPool()
	for _, rootPEM := range rootCAPems {
		roots.AppendCertsFromPEM(rootPEM)
	}

	verifyRootCAOpts := x509.VerifyOptions{
		Roots: roots,
	}


	for _, certPem := range certPemSlice {
		var cert *x509.Certificate
		var err error
		cert, verifyRootCAOpts.Intermediates, err = crypt.GetCertAndChainFromPem(certPem)
		if err != nil {
			log.Errorf("verifier/util/util:VerifyCertificateSignature() Error while retrieving certificate and intermediates")
			continue
		}

		if !(cert.IsCA && cert.BasicConstraintsValid) {
			if _, err := cert.Verify(verifyRootCAOpts); err != nil  {
				log.Errorf("verifier/util/util:VerifyCertificateSignature() Error while verifying certificate chain: %s", err.Error())
				continue
			}
		}
	        
		pubKey, err := crypt.GetPublicKeyFromCert(cert)
        	if err != nil {
			log.Errorf("verifier/util/util:VerifyCertificateSignature() Unable to retrieve public key from certificate: %s", err.Error())
                	continue
        	}
        	
		rsaPublicKey := pubKey.(*rsa.PublicKey)
	        imageFlavor.Image = flavor.ImageFlavor
        	h := sha512.New384()
	        flavorBytes, err := json.Marshal(imageFlavor)
        	if err != nil {
                	log.Errorf("verifier/util/util:VerifyCertificateSignature() Error marshalling flavor interface to bytes: %s", err.Error())
	                continue
        	}
	        h.Write(flavorBytes)
        	digest := h.Sum(nil)

	        signatureBytes, err := base64.StdEncoding.DecodeString(flavor.Signature)
        	if err != nil {
                	log.Errorf("verifier/util/util:VerifyCertificateSignature() Error decoding signature to bytes %s", err.Error())
	                continue
        	}

	        err = rsa.VerifyPKCS1v15(rsaPublicKey, crypto.SHA384, digest, signatureBytes)
        	if err != nil {
                	log.Errorf("verifier/util/util:VerifyCertificateSignature() Could not verify flavor: `%s`", err.Error())
	                continue
	        }
		log.Info("verifier/util/util:VerifyCertificateSignature() Succesfully verified the flavor signature")
		return true
	}
	log.Info("verifier/util/util:VerifyCertificateSignature() Flavor signature verification failed")
	return false
}

func getCertificate(signingCertPems interface{}) ([][]byte, error){
	var certPemSlice [][]byte

        switch signingCertPems.(type) {
        case nil:
                return nil, errors.New("Empty ")
        case [][]byte:
                certPemSlice = signingCertPems.([][]byte)
        case []byte:
                certPemSlice = [][]byte{signingCertPems.([]byte)}
        default:
                log.Errorf("signingCertPems has to be of type []byte or [][]byte")
                return nil, errors.New("signingCertPems has to be of type []byte or [][]byte")

        }
	return certPemSlice, nil
}

//VerifyFlavorIntegrity is used to verify the integrity of the flavor
func VerifyFlavorIntegrity(flavor flvr.SignedImageFlavor, signingCertsDir, trustedCAsDir string) bool {

	signingCertPems, err := cos.GetDirFileContents(signingCertsDir, "*.pem" )
	if err != nil{
		log.Errorf("verifier/util:VerifyFlavorIntegrity() Error while reading certificates from dir: %s", signingCertsDir)
		return false
	}
	
	rootPems, err := cos.GetDirFileContents(trustedCAsDir, "*.pem" )
	if err != nil{
		log.Errorf("verifier/util:VerifyFlavorIntegrity() Error while reading certificates from dir: %s", trustedCAsDir)
		return false
	}

	certPemSlice, err := getCertificate(signingCertPems)

	if err != nil {
		log.Errorf("Error while retrieving certificate")
		return false
	}

	if !verifyFlavorSignatureWithCertChainVerification(flavor, certPemSlice, rootPems){
		return false
	}
	log.Info("verifier/util/util:VerifyFlavorIntegrity() Flavor integrity verified succesfully returing true")		
	return true
}


