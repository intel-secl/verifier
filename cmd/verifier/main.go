package main

import (
	"encoding/json"
	"fmt"
	"intel/isecl/lib/common/pkg/instance"
	"intel/isecl/lib/common/validation"
	"intel/isecl/lib/flavor"
	"intel/isecl/lib/verifier"
	"io/ioutil"
	"os"
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
