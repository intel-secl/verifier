module intel/isecl/lib/verifier

require (
	github.com/sirupsen/logrus v1.4.0
	github.com/stretchr/testify v1.3.0
	intel/isecl/lib/common v0.0.0
	intel/isecl/lib/flavor v0.0.0
)

replace intel/isecl/lib/common => gitlab.devtools.intel.com/sst/isecl/lib/common.git v0.0.0-20191021091828-a7ff2a0b747b

replace intel/isecl/lib/flavor => gitlab.devtools.intel.com/sst/isecl/lib/flavor.git v0.0.0-20190915015315-7d9923b58ff3
