# verifier
--
    import "."


## Usage

#### func  Verify

```go
func Verify(manifest interface{}, flavor interface{}) (interface{}, error)
```

#### type VMTrustReport

```go
type VMTrustReport struct {
	Manifest   vm.Manifest   `json:"vm_manifest"`
	PolicyName string        `json:"policy_name"`
	Results    []rule.Result `json:"results"`
	Trusted    bool          `json:"trusted"`
}
```

VMTrustReport is a record that indicates trust status of a VM image

#### func  VerifyVM

```go
func VerifyVM(manifest *vm.Manifest, flavor *flvr.ImageFlavor) (*VMTrustReport, error)
```
VerifyVM explicity verifies a VM Manifest against a VM ImageFlavor, and returns
a VMTrustReport
