package verifier

import (
	"intel/isecl/lib/common/pkg/container"
)

// VMTrustReport is a record that indicates trust status of a VM image
type ContainerTrustReport struct {
	Manifest   container.Manifest `json:"container_manifest"`
	PolicyName string             `json:"policy_name"`
	Results    []Result           `json:"results"`
	Trusted    bool               `json:"trusted"`
}
