package verifier

import (
	"encoding/json"
	//"fmt"
	flavorUtil "intel/isecl/lib/flavor/util"
	"os"
	"intel/isecl/lib/common/pkg/instance"
	"intel/isecl/lib/flavor"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVerify(t *testing.T) {
	var signedFlavor flavorUtil.SignedImageFlavor
	currDir, _ := os.Getwd()
	flavor, err := flavor.GetImageFlavor("Cirros-enc", true,
		"http://10.1.68.21:20080/v1/keys/73755fda-c910-46be-821f-e8ddeab189e9/transfer", "261209df1789073192285e4e408addadb35068421ef4890a5d4d434")
	assert.NoError(t, err)
	flavorBytes, _ := json.Marshal(flavor)
	signedFlavorString, err := flavorUtil.GetSignedFlavor(string(flavorBytes), currDir + "/test/flavor-signing-key.pem")
	assert.NoError(t, err)
	manifest := instance.Manifest{InstanceInfo: instance.Info{InstanceID: "7B280921-83F7-4F44-9F8D-2DCF36E7AF33", HostHardwareUUID: "59EED8F0-28C5-4070-91FC-F5E2E5443F6B", ImageID: "670F263E-B34E-4E07-A520-40AC9A89F62D"}, ImageEncrypted: true}
	json.Unmarshal([]byte(signedFlavorString), &signedFlavor)
	report, err := Verify(&manifest, &signedFlavor, currDir + "/test/flavor-signing-cert.pem")
	assert.NoError(t, err)
	assert.NotNil(t, report)
	trustReport, ok := report.(*InstanceTrustReport)
	//reportJSON, _ := json.Marshal(trustReport)
	//fmt.Println(string(reportJSON))
	assert.True(t, ok)
	assert.True(t, trustReport.Trusted)
	assert.Len(t, trustReport.Results, 2)
	assert.Equal(t, trustReport.Results[0].Rule.Name(), "EncryptionMatches")
	assert.Equal(t, trustReport.Results[1].Rule.Name(), "FlavorIntegrityMatches")
}

func TestJSON(t *testing.T) {
	var signedFlavor flavorUtil.SignedImageFlavor
	currDir, _ := os.Getwd()
	flavor, err := flavor.GetImageFlavor("Cirros-enc", true,
		"http://10.1.68.21:20080/v1/keys/73755fda-c910-46be-821f-e8ddeab189e9/transfer", "261209df1789073192285e4e408addadb35068421ef4890a5d4d434")
	assert.NoError(t, err)
	flavorBytes, _ := json.Marshal(flavor)
	signedFlavorString, err := flavorUtil.GetSignedFlavor(string(flavorBytes), currDir + "/test/flavor-signing-key.pem")
	assert.NoError(t, err)
	manifest := instance.Manifest{InstanceInfo: instance.Info{InstanceID: "7B280921-83F7-4F44-9F8D-2DCF36E7AF33", HostHardwareUUID: "59EED8F0-28C5-4070-91FC-F5E2E5443F6B", ImageID: "670F263E-B34E-4E07-A520-40AC9A89F62D"}, ImageEncrypted: true}
	json.Unmarshal([]byte(signedFlavorString), &signedFlavor)
	report, err := Verify(&manifest, &signedFlavor, currDir + "/test/flavor-signing-cert.pem")
	reportJSON, _ := json.Marshal(report)
	t.Log(string(reportJSON))
	var r InstanceTrustReport
	err = json.Unmarshal(reportJSON, &r)
	assert.NoError(t, err)
	assert.True(t, r.Results[0].Trusted)
}

func TestVerifyWithFault(t *testing.T) {
	var signedFlavor flavorUtil.SignedImageFlavor
	currDir, _ := os.Getwd()
	flavor, err := flavor.GetImageFlavor("Cirros-enc", true,
		"http://10.1.68.21:20080/v1/keys/73755fda-c910-46be-821f-e8ddeab189e9/transfer", "261209df1789073192285e4e408addadb35068421ef4890a5d4d434")
	assert.NoError(t, err)
	flavorBytes, _ := json.Marshal(flavor)
	signedFlavorString, err := flavorUtil.GetSignedFlavor(string(flavorBytes), currDir + "/test/flavor-signing-key.pem")
	assert.NoError(t, err)
	manifest := instance.Manifest{InstanceInfo: instance.Info{InstanceID: "7B280921-83F7-4F44-9F8D-2DCF36E7AF33", HostHardwareUUID: "59EED8F0-28C5-4070-91FC-F5E2E5443F6B", ImageID: "670F263E-B34E-4E07-A520-40AC9A89F62D"}, ImageEncrypted: false}
	json.Unmarshal([]byte(signedFlavorString), &signedFlavor)
	report, err := Verify(&manifest, &signedFlavor, currDir + "/test/flavor-signing-cert.pem")
	assert.NoError(t, err)
	assert.NotNil(t, report)
	trustReport, ok := report.(*InstanceTrustReport)
	assert.True(t, ok)
	assert.False(t, trustReport.Trusted)
}

func TestVerifyWithConverseFault(t *testing.T) {
	var signedFlavor flavorUtil.SignedImageFlavor
	currDir, _ := os.Getwd()
	flavor, err := flavor.GetImageFlavor("Cirros-enc", false,
		"http://10.1.68.21:20080/v1/keys/73755fda-c910-46be-821f-e8ddeab189e9/transfer", "261209df1789073192285e4e408addadb35068421ef4890a5d4d434")
	assert.NoError(t, err)
	flavorBytes, _ := json.Marshal(flavor)
	signedFlavorString, err := flavorUtil.GetSignedFlavor(string(flavorBytes), currDir + "/test/flavor-signing-key.pem")
	assert.NoError(t, err)
	manifest := instance.Manifest{InstanceInfo: instance.Info{InstanceID: "7B280921-83F7-4F44-9F8D-2DCF36E7AF33", HostHardwareUUID: "59EED8F0-28C5-4070-91FC-F5E2E5443F6B", ImageID: "670F263E-B34E-4E07-A520-40AC9A89F62D"}, ImageEncrypted: true}
	json.Unmarshal([]byte(signedFlavorString), &signedFlavor)
	report, err := Verify(&manifest, &signedFlavor, currDir + "/test/flavor-signing-cert.pem")
	assert.NoError(t, err)
	assert.NotNil(t, report)

	trustReport, ok := report.(*InstanceTrustReport)
	assert.True(t, ok)
	assert.False(t, trustReport.Trusted)
}
