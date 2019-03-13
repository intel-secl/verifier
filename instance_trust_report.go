package verifier

import (
	"intel/isecl/lib/common/pkg/instance"
)

// ImageTrustReport is a record that indicates trust status of an image
type InstanceTrustReport struct {
	Manifest   instance.Manifest `json:"instance_manifest"`
	PolicyName string         `json:"policy_name"`
	Results    []Result       `json:"results"`
	Trusted    bool           `json:"trusted"`
}
