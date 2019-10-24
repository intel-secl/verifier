/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package verifier

import (
	flvr "intel/isecl/lib/flavor"
	verifierUtil "intel/isecl/lib/verifier/util"
)

// FlavorIntegrityMatches is a rule that enforces flavor integrity policy
type FlavorIntegrityMatches struct {
	RuleName              string                  `json:"rule_name"`
	Markers               []string                `json:"markers"`
	FlavorIntegrity       ExpectedFlavorIntegrity `json:"expected"`
	FlavorSigningCertsDir string                  `json:"-"`
	TrustedCAsDir         string                  `json:"-"`
}

// ExpectedFlavorIntegrity is a data template that defines the json tag name of the integrity requirement, and the expected boolean value
type ExpectedFlavorIntegrity struct {
	Name  string `json:"name"`
	Value bool   `json:"value"`
}

//FlavorIntegrityMatchesName contains the name of the rule for flavor signature verification
const FlavorIntegrityMatchesName = "FlavorIntegrityMatches"

func newFlavorIntegrityMatches(flavorSigningCertsDir, trustedCAsDir string) *FlavorIntegrityMatches {
	return &FlavorIntegrityMatches{
		FlavorIntegrityMatchesName,
		[]string{"flavorIntegrity"},
		ExpectedFlavorIntegrity{
			"flavor_trusted",
			true,
		},
		flavorSigningCertsDir,
		trustedCAsDir,
	}
}

// Name returns the name of the FlavorIntegrityMatches Rule.
func (em *FlavorIntegrityMatches) Name() string {
	return em.RuleName
}

func (em *FlavorIntegrityMatches) apply(flavor interface{}) (bool, []Fault) {
	// verify if flavor is trusted
	flavorTrusted := verifierUtil.VerifyFlavorIntegrity(flavor.(flvr.SignedImageFlavor), em.FlavorSigningCertsDir, em.TrustedCAsDir)

	// if rule expects integrity_enforced to be true
	if flavorTrusted {
		return true, nil
	} else {
		return false, []Fault{Fault{"Flavor is not trusted", nil}}
	}
}
