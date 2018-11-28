package verifier

import (
	"errors"
	"intel/isecl/lib/common/pkg/vm"
	flvr "intel/isecl/lib/flavor"
	"intel/isecl/lib/verifier/internal/rule"
)

func Verify(manifest interface{}, flavor interface{}) (interface{}, error) {
	switch flavor := flavor.(type) {
	case *flvr.ImageFlavor:
		// assert manifest as VM Manifest
		if vmManifest, ok := manifest.(*vm.Manifest); ok {
			return VerifyVM(vmManifest, flavor)
		} else {
			return nil, errors.New("supplied manifest is not a VMManifest")
		}
	default:
		return nil, errors.New("unrecognized flavor type")
	}
}

// VerifyVM explicity verifies a VM Manifest against a VM ImageFlavor, and returns a VMTrustReport
func VerifyVM(manifest *vm.Manifest, flavor *flvr.ImageFlavor) (*VMTrustReport, error) {
	// just load the single rule
	r := rule.NewEncryptionMatches(flavor.Image.Encryption.EncryptionRequired)
	trust, faults := r.Apply(manifest)
	result := rule.Result{Rule: r, FlavorID: flavor.Image.Meta.ID, Faults: faults}
	return &VMTrustReport{*manifest, "Intel VM Policy", []rule.Result{result}, trust}, nil
}
