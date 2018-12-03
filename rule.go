package verifier

// Fault defines failure events when applying a Rule
type Fault struct {
	Description string `json:"description"`
	Cause       error  `json:"cause"`
}

// Result is a struct that indicates the evaluation conclusion of applying a rule against a manifest.
// The FlavorID from which the rule derived from is included as well.
type Result struct {
	// Rule is an interface, and can be any concrete interface. You will need to apply a type assertion based on what it is if you need to access it's fields.
	Rule     Rule    `json:"rule"`
	FlavorID string  `json:"flavor_id"`
	Faults   []Fault `json:"faults,omitempty"`
	Trusted  bool    `json:"trusted"`
}

// Rule defines a trust rule to apply to a manifest.
type Rule interface {
	Name() string
	// apply is not exported publicly
	apply(actual interface{}) (bool, []Fault)
}
