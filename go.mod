module intel/isecl/lib/verifier/v3

require (
	github.com/intel-secl/intel-secl/v3 v3.6.1
	github.com/sirupsen/logrus v1.4.0
	github.com/stretchr/testify v1.6.1
	intel/isecl/lib/common/v3 v3.6.1
	intel/isecl/lib/flavor/v3 v3.6.1
)

replace (
	 intel/isecl/lib/common/v3 => github.com/intel-secl/common/v3 v3.6.1
	 intel/isecl/lib/flavor/v3 => github.com/intel-secl/flavor/v3 v3.6.1
)
