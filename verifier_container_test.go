package verifier

import (
	"encoding/json"
	"fmt"
	"intel/isecl/lib/common/pkg/image"
	"intel/isecl/lib/flavor"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVerifyContainer(t *testing.T) {
	flavor, err := flavor.GetContainerImageFlavor("Hello-World:latest", true,
		"http://10.1.68.21:20080/v1/keys/73755fda-c910-46be-821f-e8ddeab189e9/transfer", true, "https://notary.docker.io")
	assert.NoError(t, err)
	manifest := image.Manifest{ImageInfo: image.Info{InstanceID: "7B280921-83F7-4F44-9F8D-2DCF36E7AF33", HostHardwareUUID: "59EED8F0-28C5-4070-91FC-F5E2E5443F6B", ImageID: "670F263E-B34E-4E07-A520-40AC9A89F62D"}, ImageEncrypted: true, ImageIntegrityEnforced: true}
	report, err := Verify(&manifest, flavor)
	assert.NoError(t, err)
	assert.NotNil(t, report)
	trustReport, ok := report.(*ImageTrustReport)
	reportJSON, _ := json.Marshal(trustReport)
	fmt.Println(string(reportJSON))
	assert.True(t, ok)
	assert.True(t, trustReport.Trusted)
	assert.Len(t, trustReport.Results, 2)
	assert.Equal(t, trustReport.Results[0].Rule.Name(), "EncryptionMatches")
	assert.Equal(t, trustReport.Results[1].Rule.Name(), "IntegrityMatches")
}
