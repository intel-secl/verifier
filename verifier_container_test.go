/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package verifier

import (
	"encoding/json"
	"fmt"
	flvr "intel/isecl/lib/flavor"
	flavorUtil "intel/isecl/lib/flavor/util"
	"intel/isecl/lib/common/pkg/instance"
	"intel/isecl/lib/flavor"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVerifyContainer(t *testing.T) {
	var signedFlavor flvr.SignedImageFlavor
	currDir, _ := os.Getwd()
	flavor, err := flavor.GetContainerImageFlavor("Hello-World:latest", true,
		"https://10.1.68.21:20080/v1/keys/73755fda-c910-46be-821f-e8ddeab189e9/transfer", true, "https://notary.docker.io")
	assert.NoError(t, err)
	flavorBytes, _ := json.Marshal(flavor)
	signedFlavorString, err := flavorUtil.GetSignedFlavor(string(flavorBytes), currDir + "/test/flavor-signing-key.pem")
	assert.NoError(t, err)
	manifest := instance.Manifest{InstanceInfo: instance.Info{InstanceID: "7B280921-83F7-4F44-9F8D-2DCF36E7AF33", HostHardwareUUID: "59EED8F0-28C5-4070-91FC-F5E2E5443F6B", ImageID: "670F263E-B34E-4E07-A520-40AC9A89F62D"}, ImageEncrypted: true, ImageIntegrityEnforced: true}
	json.Unmarshal([]byte(signedFlavorString), &signedFlavor)
	report, err := Verify(&manifest, &signedFlavor, currDir + "/test/flavor-signing-cert.pem", false)
	assert.NoError(t, err)
	assert.NotNil(t, report)
	trustReport, ok := report.(*InstanceTrustReport)
	reportJSON, _ := json.Marshal(trustReport)
	fmt.Println(string(reportJSON))
	assert.True(t, ok)
	assert.True(t, trustReport.Trusted)
	assert.Len(t, trustReport.Results, 3)
	assert.Equal(t, trustReport.Results[0].Rule.Name(), "EncryptionMatches")
	assert.Equal(t, trustReport.Results[1].Rule.Name(), "IntegrityMatches")
	assert.Equal(t, trustReport.Results[2].Rule.Name(), "FlavorIntegrityMatches")
}
