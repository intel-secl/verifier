package verifier

import (
	"errors"
	"intel/isecl/lib/common/pkg/vm"
)

// EncryptionMatches is a rule that enforced VM image encryption policy from
type EncryptionMatches struct {
	RuleName string             `json:"rule_name"`
	Markers  []string           `json:"markers"`
	Expected ExpectedEncryption `json:"expected"`
}

// ExpectedEncryption is a data template that defines the json tag name of the encryption requirement, and the expected boolean value
type ExpectedEncryption struct {
	Name  string `json:"name"`
	Value bool   `json:"Value"`
}

const name = "EncryptionMatches"

func newEncryptionMatches(encryptionRequired bool) *EncryptionMatches {
	return &EncryptionMatches{
		name,
		[]string{"IMAGE"},
		ExpectedEncryption{
			"encryption_required",
			encryptionRequired,
		},
	}
}

// Name returns the name of the EncryptionMatches Rule.
func (em *EncryptionMatches) Name() string {
	return em.RuleName
}

// apply returns a true if the rule application concludes the manifest is trusted
// if it returns false, a list of Fault's are supplied explaining why.
func (em *EncryptionMatches) apply(manifest interface{}) (bool, []Fault) {
	// assert manifest as VmManifest
	if vmManifest, ok := manifest.(*vm.Manifest); ok {
		// if rule expects encryption_required to be true
		if em.Expected.Value == true {
			// then vmManifest image must be encrypted
			if vmManifest.ImageEncrypted {
				return true, nil
			}
			return false, []Fault{Fault{"encryption_required is \"true\" but VM Manifest.ImageEncrypted is \"false\"", nil}}
		}
		// encryption is not required, so ImageEncrypted can be anything
		// Need validation with spec and team if this is the right behavior - David Zech 11/27/18
		return true, nil
	}
	return false, []Fault{Fault{"invalid manifest type for rule", errors.New("failed to type assert manifest to *vm.Manifest")}}
}
