module intel/isecl/lib/verifier/v4

require (
	github.com/intel-secl/intel-secl/v4 v4.0.0
	github.com/sirupsen/logrus v1.4.0
	github.com/stretchr/testify v1.6.1
	intel/isecl/lib/common/v4 v4.0.0
	intel/isecl/lib/flavor/v4 v4.0.0
)

replace (
	 intel/isecl/lib/common/v3 => github.com/intel-secl/common/v4 v4.0.0
	 intel/isecl/lib/flavor/v3 => github.com/intel-secl/flavor/v4 v4.0.0
)
