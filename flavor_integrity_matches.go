package verifier

import (
	flavorUtil "intel/isecl/lib/flavor/util"
	verifierUtil "intel/isecl/lib/verifier/util"
)

// FlavorIntegrityMatches is a rule that enforces flavor integrity policy
type FlavorIntegrityMatches struct {
	RuleName        string                  `json:"rule_name"`
	Markers         []string                `json:"markers"`
	FlavorIntegrity ExpectedFlavorIntegrity `json:"expected"`
	FlavorCertPath  string                  `json:"-"`
}

// ExpectedFlavorIntegrity is a data template that defines the json tag name of the integrity requirement, and the expected boolean value
type ExpectedFlavorIntegrity struct {
	Name  string `json:"name"`
	Value bool   `json:"value"`
}

const FlavorIntegrityMatchesName = "FlavorIntegrityMatches"

func newFlavorIntegrityMatches(flavorCertPath string) *FlavorIntegrityMatches {
	return &FlavorIntegrityMatches{
		FlavorIntegrityMatchesName,
		[]string{"flavorIntegrity"},
		ExpectedFlavorIntegrity{
			"flavor_trusted",
			true,
		},
		flavorCertPath,
	}
}

// Name returns the name of the FlavorIntegrityMatches Rule.
func (em *FlavorIntegrityMatches) Name() string {
	return em.RuleName
}

func (em *FlavorIntegrityMatches) apply(flavor interface{}) (bool, []Fault) {
	// verify if flavor is trusted
	flavorTrusted := verifierUtil.VerifyFlavorIntegrity(flavor.(flavorUtil.SignedImageFlavor), em.FlavorCertPath)

	// if rule expects integrity_enforced to be true
	if flavorTrusted {
		return true, nil
	} else {
		return false, []Fault{Fault{"Flavor is not trusted", nil}}
	}
}
