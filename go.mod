module intel/isecl/lib/verifier/v4

require (
	github.com/intel-secl/intel-secl/v4 v4.2.0
	github.com/sirupsen/logrus v1.4.0
	github.com/stretchr/testify v1.6.1
	intel/isecl/lib/common/v4 v4.2.0
	intel/isecl/lib/flavor/v4 v4.2.0
)

replace (
	intel/isecl/lib/common/v4 => gitlab.devtools.intel.com/sst/isecl/lib/common.git/v4 v4.2/develop
	intel/isecl/lib/flavor/v4 => gitlab.devtools.intel.com/sst/isecl/lib/flavor.git/v4 v4.2/develop
	github.com/intel-secl/intel-secl/v4 => gitlab.devtools.intel.com/sst/isecl/intel-secl.git/v4 v4.2/develop
)
