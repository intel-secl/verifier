package verifier

import (
	"intel/isecl/lib/common/pkg/vm"
	"intel/isecl/lib/verifier/internal/rule"
)

// VMTrustReport is a record that indicates trust status of a VM image
type VMTrustReport struct {
	Manifest   vm.Manifest   `json:"vm_manifest"`
	PolicyName string        `json:"policy_name"`
	Results    []rule.Result `json:"results"`
	Trusted    bool          `json:"trusted"`
}
