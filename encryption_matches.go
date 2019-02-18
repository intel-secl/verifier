package verifier

import (
	"errors"
	"intel/isecl/lib/common/pkg/container"
	"intel/isecl/lib/common/pkg/vm"
)

// EncryptionMatches is a rule that enforces image encryption policy
type EncryptionMatches struct {
	RuleName string             `json:"rule_name"`
	Markers  []string           `json:"markers"`
	Expected ExpectedEncryption `json:"expected"`
}

// ExpectedEncryption is a data template that defines the json tag name of the encryption requirement, and the expected boolean value
type ExpectedEncryption struct {
	Name  string `json:"name"`
	Value bool   `json:"value"`
}

const EncryptionMatchesName = "EncryptionMatches"

func newEncryptionMatches(imageType string, encryptionRequired bool) *EncryptionMatches {
	return &EncryptionMatches{
		EncryptionMatchesName,
		[]string{imageType},
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
		} else {
			if vmManifest.ImageEncrypted == false {
				return true, nil
			}
			return false, []Fault{Fault{"encryption_required is \"false\" but VM Manifest.ImageEncrypted is \"true\"", nil}}
		}
	} else if containerManifest, ok := manifest.(*container.Manifest); ok {
		// if rule expects encryption_required to be true
		if em.Expected.Value == true {
			// then vmManifest image must be encrypted
			if containerManifest.ImageEncrypted {
				return true, nil
			}
			return false, []Fault{Fault{"encryption_required is \"true\" but Container Manifest.ImageEncrypted is \"false\"", nil}}
		} else {
			if containerManifest.ImageEncrypted == false {
				return true, nil
			}
			return false, []Fault{Fault{"encryption_required is \"false\" but Container Manifest.ImageEncrypted is \"true\"", nil}}
		}
	}
	return false, []Fault{Fault{"invalid manifest type for rule", errors.New("failed to type assert manifest to *vm.Manifest/container.Manifest")}}
}
