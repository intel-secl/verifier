/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package verifier

import (
	"intel/isecl/lib/common/v2/pkg/instance"
)

// ImageTrustReport is a record that indicates trust status of an image
type InstanceTrustReport struct {
	Manifest   instance.Manifest `json:"instance_manifest"`
	PolicyName string         `json:"policy_name"`
	Results    []Result       `json:"results"`
	Trusted    bool           `json:"trusted"`
}
