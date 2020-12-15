/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package main

import (
	"encoding/json"
	"fmt"
	"intel/isecl/lib/common/v3/pkg/instance"
	"intel/isecl/lib/common/v3/validation"
	"intel/isecl/lib/flavor/v3"
	"intel/isecl/lib/verifier/v3"
	"io/ioutil"
	"os"
	"strconv"
)

func printUsage() {
	fmt.Println(os.Args[0], "[options]")
	fmt.Println("Verify <manifest.json> <flavor.json> <flavor Signing Certificate Path> <skip flavor signature verification (true/false)>")
	fmt.Println("\tOutput: <Trust Report Json>")
}

func verify(manifestPath, flavorPath, flavorSigningCertsDir, trustedCAsDir string, skipFlavorSignatureVerification bool) {
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

	trustreport, err := verifier.Verify(&manifest, &flv, flavorSigningCertsDir, trustedCAsDir, skipFlavorSignatureVerification)
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
		if len(param) != 5 {
			printUsage()
		} else {
			if param[4] != "true" && param[4] != "false" {
				printUsage()
			}
			flavorSignatureVerificationSkip, err := strconv.ParseBool(param[4])
			if err != nil {
				printUsage()
			} else {
				verify(param[0], param[1], param[2], param[3], flavorSignatureVerificationSkip)
			}
		}
	default:
		printUsage()
	}
}
