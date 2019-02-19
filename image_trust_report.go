package verifier

import (
	"intel/isecl/lib/common/pkg/image"
)

// ImageTrustReport is a record that indicates trust status of an image
type ImageTrustReport struct {
	Manifest   image.Manifest `json:"image_manifest"`
	PolicyName string         `json:"policy_name"`
	Results    []Result       `json:"results"`
	Trusted    bool           `json:"trusted"`
}
