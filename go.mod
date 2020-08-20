module intel/isecl/lib/verifier/v3

require (
	github.com/intel-secl/intel-secl/v3 v3.0.0
	github.com/sirupsen/logrus v1.4.0
	github.com/stretchr/testify v1.3.0
	intel/isecl/lib/common/v3 v3.0.0
	intel/isecl/lib/flavor/v3 v3.3.0
)

replace intel/isecl/lib/common/v3 =>  gitlab.devtools.intel.com/sst/isecl/lib/common.git/v3 v3.0/develop

replace intel/isecl/lib/flavor/v3 => gitlab.devtools.intel.com/sst/isecl/lib/flavor.git/v3 v3.0/develop

replace github.com/intel-secl/intel-secl/v3 => gitlab.devtools.intel.com/sst/isecl/intel-secl.git/v3 v3.0/develop 
