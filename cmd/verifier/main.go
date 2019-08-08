package main

import (
	"encoding/json"
	"fmt"
	"intel/isecl/lib/common/pkg/instance"
	"intel/isecl/lib/common/validation"
	"intel/isecl/lib/flavor"
	"intel/isecl/lib/verifier"
	"io/ioutil"
	"net/url"
	"os"
	"regexp"
	"strconv"
)

func printUsage() {
	fmt.Println(os.Args[0], "[options]")
	fmt.Println("Verify <manifest.json> <flavor.json> <flavor Signing Certificate Path> <skip flavor signature verification (true/false)>")
	fmt.Println("\tOutput: <Trust Report Json>")
}

func verify(manifestPath, flavorPath, flavorSigningCertPath string, skipFlavorSignatureVerification bool) {
	inputArr := []string{manifestPath, flavorPath}
	if validateInputErr := validation.ValidateStrings(inputArr); validateInputErr != nil {
		fmt.Println("Invalid string format")
		os.Exit(1)
	}

	manifestData, err := ioutil.ReadFile(manifestPath)
	if err != nil {
		fmt.Printf("Could not read file %s\n", manifestPath)
		os.Exit(1)
	}
	var manifest instance.Manifest
	err = json.Unmarshal(manifestData, &manifest)
	if err != nil {
		fmt.Printf("Could not unmarshal json file %s\n", manifestPath)
		os.Exit(1)
	}

	flavorData, err := ioutil.ReadFile(flavorPath)
	if err != nil {
		fmt.Printf("Could not read file %s\n", flavorPath)
		os.Exit(1)
	}
	var flv flavor.ImageFlavor
	err = json.Unmarshal(flavorData, &flv)
	if err != nil {
		fmt.Printf("Could not unmarshal jsonfile %s\n", flavorPath)
		os.Exit(1)
	}
	//input validation for manifest
	if err = validation.ValidateUUIDv4(manifest.InstanceInfo.InstanceID); err != nil {
		fmt.Println("Invalid input : VmID must be a valid UUID")
		os.Exit(1)
	}

	if err = validation.ValidateHardwareUUID(manifest.InstanceInfo.HostHardwareUUID); err != nil {
		fmt.Println("Invalid input : Host hardware UUID must be valid")
		os.Exit(1)
	}

	if err = validation.ValidateUUIDv4(manifest.InstanceInfo.InstanceID); err != nil {
		fmt.Println("Invalid input : ImageID must be a valid UUID")
		os.Exit(1)
	}

	//input validation for flavor
	if err = validation.ValidateUUIDv4(flv.Image.Meta.ID); err != nil {
		fmt.Println("Invalid input : FlavorID must be a valid UUID")
		os.Exit(1)
	}

	if !isValidFlavorPart(flv.Image.Meta.Description.FlavorPart) {
		fmt.Println("Invalid input :flavor part must be IMAGE or CONTAINER_IMAGE")
		os.Exit(1)
	}

	uriValue, _ := url.Parse(flv.Image.Encryption.KeyURL)
	protocol := make(map[string]byte)
	protocol["https"] = 0
	if validateURLErr := validation.ValidateURL(flv.Image.Encryption.KeyURL, protocol, uriValue.RequestURI()); validateURLErr != nil {
		fmt.Printf("Invalid key URL format: %s\n", validateURLErr.Error())
		os.Exit(1)
	}

	if validateDigestErr := validation.ValidateBase64String(flv.Image.Encryption.Digest); validateDigestErr != nil {
		fmt.Printf("Invalid digest: %s\n", validateDigestErr.Error())
		os.Exit(1)
	}

	trustreport, err := verifier.Verify(&manifest, &flv, flavorSigningCertPath, skipFlavorSignatureVerification)
	if err != nil {
		fmt.Printf("Flavor verification encountered a runtime error: %s", err.Error())
		os.Exit(1)
	}

	trustreportJSON, err := json.MarshalIndent(trustreport, "", "    ")
	if err != nil {
		fmt.Println("Failed to marshal trustreport to json")
		os.Exit(1)
	}
	fmt.Println(string(trustreportJSON))
}

func main() {
	args := os.Args[1:]
	if len(args) <= 0 {
		printUsage()
		return
	}
	inputValArr := []string{os.Args[0], os.Args[1]}
	if valErr := validation.ValidateStrings(inputValArr); valErr != nil {
		fmt.Println("Invalid string format")
		os.Exit(1)
	}
	switch cmd := args[0]; cmd {
	case "Verify":
		param := args[1:]
		if len(param) != 4 {
			printUsage()
		} else {
			if param[3] != "true" && param[3] != "false"{
				printUsage()
			}
			flavorSignatureVerificationSkip, err := strconv.ParseBool(param[3])
			if err != nil {
				printUsage()
			} else {
				verify(param[0], param[1], param[2], flavorSignatureVerificationSkip)
			}
		}
	default:
		printUsage()
	}
}

//isValidDigest method checks if the digest value is hexadecimal and 64 characters in length
func isValidDigest(value string) bool {
	r := regexp.MustCompile("^[a-fA-F0-9]{64}$")
	return r.MatchString(value)
}

//isValidFlavorPart method checks if the flavor part is of type OS , BIOS , COMBINED, ASSET_TAG, HOST_UNIQUE
func isValidFlavorPart(flavor string) bool {
	flavorPart := [...]string{"IMAGE", "CONTAINER_IMAGE"}
	for _, a := range flavorPart {
		if a == flavor {
			return true
		}
	}
	return false
}
