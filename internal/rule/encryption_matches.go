package rule

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

// NewEncryptionMatches constructs a new EncryptionMatches rule, with encryptionRequired set as true or false
func NewEncryptionMatches(encryptionRequired bool) *EncryptionMatches {
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

func (em *EncryptionMatches) Apply(manifest interface{}) (bool, []Fault) {
	// assert manifest as VmManifest
	if vmManifest, ok := manifest.(*vm.Manifest); ok {
		// if rule expects encryption_required to be true
		if em.Expected.Value == true {
			// then vmManifest image must be encrypted
			if vmManifest.ImageEncrypted {
				return true, nil
			} else {
				return false, []Fault{Fault{"encryption_required is \"true\" but VM Manifest.ImageEncrypted is \"false\"", nil}}
			}
		} else {
			// encryption is not required, so ImageEncrypted can be anything
			// Need validation with spec and team if this is the right behavior - David Zech 11/27/18
			return true, nil
		}
	} else {
		return false, []Fault{Fault{"invalid manifest type for rule", errors.New("failed to type assert manifest to *vm.Manifest")}}
	}
}
