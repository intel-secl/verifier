module intel/isecl/lib/verifier/v4

require (
	github.com/intel-secl/intel-secl/v4 v4.1.1
	github.com/sirupsen/logrus v1.4.0
	github.com/stretchr/testify v1.6.1
	intel/isecl/lib/common/v4 v4.1.1
	intel/isecl/lib/flavor/v4 v4.1.1
)

replace (
	intel/isecl/lib/common/v4 => github.com/intel-innersource/libraries.security.isecl.common/v4 v4.1.1/develop
	intel/isecl/lib/flavor/v4 => github.com/intel-innersource/libraries.security.isecl.flavor/v4 v4.1.1/develop
	github.com/intel-secl/intel-secl/v4 => github.com/intel-innersource/applications.security.isecl.intel-secl/v4 v4.1.1/develop
)
