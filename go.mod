module intel/isecl/lib/verifier/v2

require (
	github.com/sirupsen/logrus v1.4.0
	github.com/stretchr/testify v1.3.0
	intel/isecl/lib/common/v2 v2.2.1
	intel/isecl/lib/flavor/v2 v2.2.1
)

replace intel/isecl/lib/common/v2 => github.com/intel-secl/common/v2 v2.2.1

replace intel/isecl/lib/flavor/v2 => github.com/intel-secl/flavor/v2 v2.2.1
