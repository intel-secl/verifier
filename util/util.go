package util

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io/ioutil"

	flvr "intel/isecl/lib/flavor"
	flavorUtil "intel/isecl/lib/flavor/util"

	log "github.com/sirupsen/logrus"
)

//VerifyFlavorIntegrity is used to verify the integrity of the flavor
func VerifyFlavorIntegrity(flavor flavorUtil.SignedImageFlavor, certificateFilePath string) bool {

	var imageFlavor flvr.ImageFlavor
	if certificateFilePath == "" {
		log.Error("No certificate file path provided")
		return false
	}

	certificate, err := ioutil.ReadFile(certificateFilePath)
	if err != nil {
		log.Error("Cannot read certificate from file")
		return false
	}

	certificatePem, _ := pem.Decode(certificate)
	cert, err := x509.ParseCertificate(certificatePem.Bytes)
	if err != nil {
		log.Error("Cannot parse bytes as certificate")
		return false
	}

	rsaPublicKey := cert.PublicKey.(*rsa.PublicKey)
	imageFlavor.Image = flavor.ImageFlavor
	h := sha512.New384()
	flavorBytes, err := json.Marshal(imageFlavor)
	if err != nil {
		log.Error("Error marshalling flavor interface to bytes")
		return false
	}
	h.Write(flavorBytes)
	digest := h.Sum(nil)

	signatureBytes, err := base64.StdEncoding.DecodeString(flavor.Signature)
	if err != nil {
		log.Error("Error decoding signature to bytes")
		return false
	}

	err = rsa.VerifyPKCS1v15(rsaPublicKey, crypto.SHA384, digest, signatureBytes)
	if err != nil {
		log.Errorf("Could not verify flavor: `%s` (digest: `%v`)", err, digest)
		return false
	}

	return true

}
