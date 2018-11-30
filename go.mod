module intel/isecl/lib/verifier

require intel/isecl/lib/flavor v0.0.0

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/stretchr/objx v0.1.1 // indirect
	github.com/stretchr/testify v1.2.2
	intel/isecl/lib/common v0.0.0
)

replace intel/isecl/lib/flavor => gitlab.devtools.intel.com/sst/isecl/lib/flavor v0.0.0-20181130040149-7faec88186a3

replace intel/isecl/lib/common => gitlab.devtools.intel.com/sst/isecl/lib/common v0.0.0-20181121191214-b6cb5d0ef496
