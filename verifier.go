package verifier

import (
	"errors"
	"intel/isecl/lib/common/pkg/container"
	"intel/isecl/lib/common/pkg/vm"
	flvr "intel/isecl/lib/flavor"
)

// Verify verifies a manifest against a flavor.
// manifest and flavor are both interface{}, but must be able to be type asserted (downcasted) to one of the following:
// manifest:
// - *(vm/ctns).Manifest
// flavor:
// - *flavor.ImageFlavor
// More types will be supported as the feature set is expanded in this library
// Verify returns an interface{} which is a concrete type of any of the following:
// - *(VM/CTNS)TrustReport
func Verify(manifest interface{}, flavor interface{}) (interface{}, error) {
	switch flavor := flavor.(type) {
	case *flvr.ImageFlavor:
		// assert manifest as VM Manifest
		if vmManifest, ok := manifest.(*vm.Manifest); ok {
			return VerifyVM(vmManifest, flavor)
		}
		if containerManifest, ok := manifest.(*container.Manifest); ok {
			return VerifyContainer(containerManifest, flavor)
		}
		return nil, errors.New("supplied manifest is not a VMManifest")
	default:
		return nil, errors.New("unrecognized flavor type")
	}
}

// VerifyVM explicity verifies a VM Manifest against a VM ImageFlavor, and returns a VMTrustReport
func VerifyVM(manifest *vm.Manifest, flavor *flvr.ImageFlavor) (*VMTrustReport, error) {
	// just load the single rule
	r := newEncryptionMatches("VM_IMAGE", flavor.Image.Encryption.EncryptionRequired)
	trust, faults := r.apply(manifest)
	result := Result{Rule: r, FlavorID: flavor.Image.Meta.ID, Faults: faults, Trusted: trust}
	// TrustReport is Trusted if all rule applications result in trust == true
	return &VMTrustReport{*manifest, "Intel VM Policy", []Result{result}, result.Trusted}, nil
}

// VerifyContainer explicity verifies a Container Manifest against a Container ImageFlavor, and returns a ContainerTrustReport
func VerifyContainer(manifest *container.Manifest, flavor *flvr.ImageFlavor) (*ContainerTrustReport, error) {
	var result []Result
	// just load the single rule
	encryptionRule := newEncryptionMatches("CONTAINER_IMAGE", flavor.Image.Encryption.EncryptionRequired)
	trust, faults := encryptionRule.apply(manifest)
	result = append(result, Result{Rule: encryptionRule, FlavorID: flavor.Image.Meta.ID, Faults: faults, Trusted: trust})
	// just load the single rule
	integrityRule := newIntegrityMatches("CONTAINER_IMAGE", flavor.Image.Integrity.IntegrityEnforced)
	trust, faults = integrityRule.apply(manifest)
	result = append(result, Result{Rule: integrityRule, FlavorID: flavor.Image.Meta.ID, Faults: faults, Trusted: trust})
	//get consolidated trust status
	isTrusted := getTrustStatus(result)
	// TrustReport is Trusted if all rule applications result in trust == true
	return &ContainerTrustReport{*manifest, "Intel Container Policy", result, isTrusted}, nil
}

//returns consolidated trust status in case of multiple rule validation
func getTrustStatus(result []Result) bool {
	isTrusted := true
	//if no result is generated
	if len(result) <= 0 {
		return false
	}
	for _, element := range result {
		isTrusted = isTrusted && element.Trusted
	}
	return isTrusted
}
