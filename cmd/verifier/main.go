package main

import (
	"encoding/json"
	"fmt"
	"intel/isecl/lib/common/pkg/vm"
	"intel/isecl/lib/flavor"
	"intel/isecl/lib/verifier"
	"io/ioutil"
	"log"
	"net/url"
	"os"
	"regexp"
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
	//input validation for manifest
	if !isValidUUID(manifest.VmInfo.VmID) {
		log.Fatal("Invalid input : VmID must be a valid UUID.")
	}
	if !isValidUUID(manifest.VmInfo.HostHardwareUUID) {
		log.Fatal("Invalid input : HostHardwareUUID must be a valid UUID.")
	}
	if !isValidUUID(manifest.VmInfo.ImageID) {
		log.Fatal("Invalid input : ImageID must be a valid UUID.")
	}

	//input validation for flavor
	if !isValidUUID(flv.Image.Meta.ID) {
		log.Fatal("Invalid input : FlavorID must be a valid UUID.")
	}
	if !isValidFlavorPart(flv.Image.Meta.Description.FlavorPart) {
		log.Fatal("Invalid input :flavor part must be OS , BIOS, ASSET_TAG, SOFTWARE")
	}
	_, err = url.ParseRequestURI(flv.Image.Encryption.KeyURL)
	if err != nil {
		log.Fatal("Invalid input : keyURL")
	}
	if !isValidDigest(flv.Image.Encryption.Digest) {
		log.Fatal("Invalid input : digest must be a hexadecimal value and 64 characters in length.")
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

//isValidDigest method checks if the digest value is hexadecimal and 64 characters in length
func isValidDigest(value string) bool {
	r := regexp.MustCompile("^[a-fA-F0-9]{64}$")
	return r.MatchString(value)
}

//isValidUUID method checks if the UUID is valid
func isValidUUID(uuid string) bool {
	r := regexp.MustCompile("^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}$")
	return r.MatchString(uuid)
}

//isValidFlavorPart method checks if the flavor part is of type OS , BIOS , COMBINED, ASSET_TAG, HOST_UNIQUE
func isValidFlavorPart(flavor string) bool {
	flavorPart := [...]string{"OS", "BIOS", "ASSET_TAG", "HOST_UNIQUE", "SOFTWARE"}
	for _, a := range flavorPart {
		if a == flavor {
			return true
		}
	}
	return false
}
