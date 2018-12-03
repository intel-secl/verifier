package verifier

import (
	"errors"
	"intel/isecl/lib/common/pkg/vm"
	flvr "intel/isecl/lib/flavor"
)

// Verify verifies a manifest against a flavor.
// manifest and flavor are both interface{}, but must be able to be type asserted (downcasted) to one of the following:
// manifest:
// - *vm.Manifest
// flavor:
// - *flavor.ImageFlavor
// More types will be supported as the feature set is expanded in this library
// Verify returns an interface{} which is a concrete type of any of the following:
// - *VMTrustReport
func Verify(manifest interface{}, flavor interface{}) (interface{}, error) {
	switch flavor := flavor.(type) {
	case *flvr.ImageFlavor:
		// assert manifest as VM Manifest
		if vmManifest, ok := manifest.(*vm.Manifest); ok {
			return VerifyVM(vmManifest, flavor)
		}
		return nil, errors.New("supplied manifest is not a VMManifest")
	default:
		return nil, errors.New("unrecognized flavor type")
	}
}

// VerifyVM explicity verifies a VM Manifest against a VM ImageFlavor, and returns a VMTrustReport
func VerifyVM(manifest *vm.Manifest, flavor *flvr.ImageFlavor) (*VMTrustReport, error) {
	// just load the single rule
	r := newEncryptionMatches(flavor.Image.Encryption.EncryptionRequired)
	trust, faults := r.apply(manifest)
	result := Result{Rule: r, FlavorID: flavor.Image.Meta.ID, Faults: faults, Trusted: trust}
	// TrustReport is Trusted if all rule applications result in trust == true
	return &VMTrustReport{*manifest, "Intel VM Policy", []Result{result}, result.Trusted}, nil
}
