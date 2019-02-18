package verifier

import (
	"errors"
	"intel/isecl/lib/common/pkg/container"
)

// IntegrityMatches is a rule that enforces container image encryption and integrity policy from
type IntegrityMatches struct {
	RuleName          string            `json:"rule_name"`
	Markers           []string          `json:"markers"`
	IntegrityEnforced ExpectedIntegrity `json:"enforced"`
}

// ExpectedEncryption is a data template that defines the json tag name of the encryption requirement, and the expected boolean value
type ExpectedIntegrity struct {
	Name  string `json:"name"`
	Value bool   `json:"value"`
}

const IntegrityMatchesName = "IntegrityMatches"

func newIntegrityMatches(imageType string, integrityEnforced bool) *IntegrityMatches {
	return &IntegrityMatches{
		IntegrityMatchesName,
		[]string{imageType},
		ExpectedIntegrity{
			"integrity_enforced",
			integrityEnforced,
		},
	}
}

// Name returns the name of the EncryptionMatches Rule.
func (em *IntegrityMatches) Name() string {
	return em.RuleName
}

// apply returns a true if the rule application concludes the manifest is trusted
// if it returns false, a list of Fault's are supplied explaining why.
func (em *IntegrityMatches) apply(manifest interface{}) (bool, []Fault) {
	// assert manifest as VmManifest
	if Manifest, ok := manifest.(*container.Manifest); ok {
		// if rule expects encryption_required to be true
		if em.IntegrityEnforced.Value == true {
			// then vmManifest image must be encrypted
			if Manifest.ImageIntegrityEnforced {
				return true, nil
			}
			return false, []Fault{Fault{"integrity_enforced is \"true\" but Manifest.ImageIntegrityEnforced is \"false\"", nil}}
		} else {
			if Manifest.ImageIntegrityEnforced == false {
				return true, nil
			}
			return false, []Fault{Fault{"integrity_enforced is \"false\" but Manifest.ImageIntegrityEnforced is \"true\"", nil}}
		}
	}
	return false, []Fault{Fault{"invalid manifest type for rule", errors.New("failed to type assert manifest")}}
}
