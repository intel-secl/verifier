package main

import (
	"encoding/json"
	"fmt"
	"intel/isecl/lib/common/pkg/vm"
	"intel/isecl/lib/flavor"
	"intel/isecl/lib/verifier"
	"io/ioutil"
	"log"
	"os"
)

func printUsage() {
	fmt.Println(os.Args[0], "[options]")
	fmt.Println("Verify <manifest.json> <flavor.json>")
	fmt.Println("\tOutput: <Trust Report Json>")
}

func verify(manifestPath string, flavorPath string) {
	manifestData, err := ioutil.ReadFile(manifestPath)
	if err != nil {
		log.Fatalf("Could not read file %s\n", manifestPath)
	}
	var manifest vm.Manifest
	err = json.Unmarshal(manifestData, &manifest)
	if err != nil {
		log.Fatalf("Could not unmarshal json file %s\n", manifestPath)
	}

	flavorData, err := ioutil.ReadFile(flavorPath)
	if err != nil {
		log.Fatalf("Could not read file %s\n", flavorPath)
	}
	var flv flavor.ImageFlavor
	err = json.Unmarshal(flavorData, &flv)
	if err != nil {
		log.Fatalf("Could not unmarshal jsonfile %s\n", flavorPath)
	}

	trustreport, err := verifier.Verify(&manifest, &flv)
	if err != nil {
		log.Fatal("Flavor verification encountered a runtime error", err)
	}

	trustreportJSON, err := json.MarshalIndent(trustreport, "", "    ")
	if err != nil {
		log.Fatal("Failed to marshal trustreport to json")
	}
	log.Println(string(trustreportJSON))
}

func main() {
	args := os.Args[1:]
	if len(args) <= 0 {
		printUsage()
		return
	}
	switch cmd := args[0]; cmd {
	case "Verify":
		param := args[1:]
		if len(param) != 2 {
			printUsage()
		} else {
			verify(param[0], param[1])
		}
	default:
		printUsage()
	}
}
