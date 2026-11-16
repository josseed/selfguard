module example.com/app

go 1.21

toolchain go1.21.5

require (
	github.com/gin-gonic/gin v1.7.0
	golang.org/x/net v0.0.0-20210226172049-e18ecbb05110 // indirect
	github.com/old/thing v1.2.0
	github.com/local/fork v1.0.0
	"github.com/quoted/mod" v0.3.1 // indirect; for tests
)

require github.com/single/line v2.0.0+incompatible

replace github.com/old/thing => github.com/new/thing v1.3.0

replace github.com/local/fork v1.0.0 => ../fork

exclude github.com/gin-gonic/gin v1.6.0
