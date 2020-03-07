module intel/isecl/lib/verifier

require (
	github.com/sirupsen/logrus v1.4.0
	github.com/stretchr/testify v1.3.0
	intel/isecl/lib/common v0.0.0
	intel/isecl/lib/flavor v0.0.0
)

replace intel/isecl/lib/common => github.com/intel-secl/common v2.0.0

replace intel/isecl/lib/flavor => github.com/intel-secl/flavor v2.0.0
