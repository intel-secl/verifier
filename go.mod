module intel/isecl/lib/verifier

require (
	github.com/sirupsen/logrus v1.4.0
	github.com/stretchr/testify v1.3.0
	intel/isecl/lib/common v0.0.0
	intel/isecl/lib/flavor v0.0.0
)

replace intel/isecl/lib/flavor => gitlab.devtools.intel.com/sst/isecl/lib/flavor.git v0.0.0-20190724130420-55de0ba53dc1

replace intel/isecl/lib/common => gitlab.devtools.intel.com/sst/isecl/lib/common.git v0.0.0-20190723202540-c602a6f38a48