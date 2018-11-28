package rule

type Fault struct {
	Description string
	Cause       error
}

// Result is a struct that indicates the evaluation conclusion of applying a rule against a manifest.
// The FlavorID from which the rule derived from is included as well.
type Result struct {
	// Rule is an interface, and can be any concrete interface. You will need to apply a type assertion based on what it is if you need to access it's fields.
	Rule     Rule
	FlavorID string
	Faults   []Fault
}

// Rule defines a trust rule to apply to a manifest.
type Rule interface {
	Name() string
	Apply(actual interface{}) (bool, []Fault)
}
