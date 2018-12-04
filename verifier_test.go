package verifier

import (
	"intel/isecl/lib/common/pkg/vm"
	"intel/isecl/lib/flavor"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVerify(t *testing.T) {
	flavor, err := flavor.GetImageFlavor("Cirros-enc", true,
		"http://10.1.68.21:20080/v1/keys/73755fda-c910-46be-821f-e8ddeab189e9/transfer", "261209df1789073192285e4e408addadb35068421ef4890a5d4d434")
	assert.NoError(t, err)
	manifest := vm.Manifest{VmInfo: vm.Info{VmID: "7B280921-83F7-4F44-9F8D-2DCF36E7AF33", HostHardwareUUID: "59EED8F0-28C5-4070-91FC-F5E2E5443F6B", ImageID: "670F263E-B34E-4E07-A520-40AC9A89F62D"}, ImageEncrypted: true}
	report, err := Verify(&manifest, flavor)
	assert.NoError(t, err)
	assert.NotNil(t, report)
	vmReport, ok := report.(*VMTrustReport)
	assert.True(t, ok)
	assert.True(t, vmReport.Trusted)
	assert.Len(t, vmReport.Results, 1)
	assert.Equal(t, vmReport.Results[0].Rule.Name(), "EncryptionMatches")
}

func TestVerifyWithFault(t *testing.T) {
	flavor, err := flavor.GetImageFlavor("Cirros-enc", true,
		"http://10.1.68.21:20080/v1/keys/73755fda-c910-46be-821f-e8ddeab189e9/transfer", "261209df1789073192285e4e408addadb35068421ef4890a5d4d434")

	assert.NoError(t, err)
	manifest := vm.Manifest{VmInfo: vm.Info{VmID: "7B280921-83F7-4F44-9F8D-2DCF36E7AF33", HostHardwareUUID: "59EED8F0-28C5-4070-91FC-F5E2E5443F6B", ImageID: "670F263E-B34E-4E07-A520-40AC9A89F62D"}, ImageEncrypted: false}
	report, err := Verify(&manifest, flavor)
	assert.NoError(t, err)
	assert.NotNil(t, report)

	vmReport, ok := report.(*VMTrustReport)
	assert.True(t, ok)
	assert.False(t, vmReport.Trusted)
}

func TestVerifyWithConverseFault(t *testing.T) {
	flavor, err := flavor.GetImageFlavor("Cirros-enc", false,
		"http://10.1.68.21:20080/v1/keys/73755fda-c910-46be-821f-e8ddeab189e9/transfer", "261209df1789073192285e4e408addadb35068421ef4890a5d4d434")

	assert.NoError(t, err)
	manifest := vm.Manifest{VmInfo: vm.Info{VmID: "7B280921-83F7-4F44-9F8D-2DCF36E7AF33", HostHardwareUUID: "59EED8F0-28C5-4070-91FC-F5E2E5443F6B", ImageID: "670F263E-B34E-4E07-A520-40AC9A89F62D"}, ImageEncrypted: true}
	report, err := Verify(&manifest, flavor)
	assert.NoError(t, err)
	assert.NotNil(t, report)

	vmReport, ok := report.(*VMTrustReport)
	assert.True(t, ok)
	assert.False(t, vmReport.Trusted)
}
