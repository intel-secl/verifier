package verifier

import (
	"intel/isecl/lib/common/pkg/vm"
)

// VMTrustReport is a record that indicates trust status of a VM image
type VMTrustReport struct {
	Manifest   vm.Manifest `json:"vm_manifest"`
	PolicyName string      `json:"policy_name"`
	Results    []Result    `json:"results"`
	Trusted    bool        `json:"trusted"`
}
