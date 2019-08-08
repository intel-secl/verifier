package verifier

import (
	"errors"
	"intel/isecl/lib/common/pkg/instance"
	flvr "intel/isecl/lib/flavor"
)

// Verify verifies a manifest against a flavor.
// manifest and flavor are both interface{}, but must be able to be type asserted (downcasted) to one of the following:
// manifest:
// - *instance.Manifest
// flavor:
// - *flavor.ImageFlavor
// More types will be supported as the feature set is expanded in this library
// Verify returns an interface{} which is a concrete type of any of the following:
// - *InstanceTrustReport
func Verify(manifest interface{}, flavor interface{}, flavorSigningCertPath string, skipFlavorSignatureVerification bool) (interface{}, error) {
	var flavorPart string
	switch flavor := flavor.(type) {
	case *flvr.SignedImageFlavor:
		// assert manifest as VM Manifest
		flavorPart = flavor.ImageFlavor.Meta.Description.FlavorPart
		manifest, ok := manifest.(*instance.Manifest)
		if flavorPart == "IMAGE" && ok {
			return VerifyVM(manifest, flavor, flavorSigningCertPath, skipFlavorSignatureVerification)
		}
		if flavorPart == "CONTAINER_IMAGE" && ok {
			return VerifyContainer(manifest, flavor, flavorSigningCertPath, skipFlavorSignatureVerification)
		}
		return nil, errors.New("supplied manifest is not an instance Manifest")
	default:
		return nil, errors.New("unrecognized flavor type")
	}
}

// VerifyVM explicity verifies a VM Manifest against a VM ImageFlavor, and returns a VMTrustReport
func VerifyVM(manifest *instance.Manifest, flavor *flvr.SignedImageFlavor, flavorSigningCertPath string, skipFlavorSignatureVerification bool) (*InstanceTrustReport, error) {
	var result []Result

	r := newEncryptionMatches("IMAGE", flavor.ImageFlavor.EncryptionRequired)
	trust, faults := r.apply(manifest)
	result = append(result, Result{Rule: r, FlavorID: flavor.ImageFlavor.Meta.ID, Faults: faults, Trusted: trust})

	if !skipFlavorSignatureVerification {
		flavorIntegrityRule := newFlavorIntegrityMatches(flavorSigningCertPath)
		trust, faults = flavorIntegrityRule.apply(*flavor)
		result = append(result, Result{Rule: flavorIntegrityRule, FlavorID: flavor.ImageFlavor.Meta.ID, Faults: faults, Trusted: trust})
	}
	//get consolidated trust status
	isTrusted := getTrustStatus(result)
	// TrustReport is Trusted if all rule applications result in trust == true
	return &InstanceTrustReport{*manifest, "Intel VM Policy", result, isTrusted}, nil
}

// VerifyContainer explicity verifies a Container Manifest against a Container ImageFlavor, and returns a ContainerTrustReport
func VerifyContainer(manifest *instance.Manifest, flavor *flvr.SignedImageFlavor, flavorSigningCertPath string, skipFlavorSignatureVerification bool) (*InstanceTrustReport, error) {
	var result []Result

	encryptionRule := newEncryptionMatches("CONTAINER_IMAGE", flavor.ImageFlavor.EncryptionRequired)
	trust, faults := encryptionRule.apply(manifest)
	result = append(result, Result{Rule: encryptionRule, FlavorID: flavor.ImageFlavor.Meta.ID, Faults: faults, Trusted: trust})

	integrityRule := newIntegrityMatches("CONTAINER_IMAGE", flavor.ImageFlavor.IntegrityEnforced)
	trust, faults = integrityRule.apply(manifest)
	result = append(result, Result{Rule: integrityRule, FlavorID: flavor.ImageFlavor.Meta.ID, Faults: faults, Trusted: trust})

	if !skipFlavorSignatureVerification {
		flavorIntegrityRule := newFlavorIntegrityMatches(flavorSigningCertPath)
		trust, faults = flavorIntegrityRule.apply(*flavor)
		result = append(result, Result{Rule: flavorIntegrityRule, FlavorID: flavor.ImageFlavor.Meta.ID, Faults: faults, Trusted: trust})
	}
	//get consolidated trust status
	isTrusted := getTrustStatus(result)
	// TrustReport is Trusted if all rule applications result in trust == true
	return &InstanceTrustReport{*manifest, "Intel Container Policy", result, isTrusted}, nil
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
