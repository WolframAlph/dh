# dh

dh is a simple, ready to use Diffie-Hellman-Ephemeral implementation written in golang 
using MODP groups as defined in [RFC3526](https://datatracker.ietf.org/doc/html/rfc3526).

Example:

```go
package main

import (
	"fmt"
	"reflect"
	"github.com/WolframAlph/dh"
)
    
func main() {
	alice := dh.New()
	bob := dh.New()
	
	aliceSecret := alice.ComputeSecret(bob.PublicKey)
	bobSecret := bob.ComputeSecret(alice.PublicKey)
	
	fmt.Println(reflect.DeepEqual(aliceSecret, bobSecret)) // true
}
```

## Notes

You must use the same MODP group on both sides, or else you
end up with non-matching keys. Group #14 is used by default. You
can use different group from available (5, 14, 15, 16, 17, 18).
Example using other group:

```go
package main

import (
	"fmt"
	"reflect"
	"github.com/WolframAlph/dh"
)
    
func main() {
	modpGroup := 16
	alice := dh.New(modpGroup)
	bob := dh.New(modpGroup)
	
	aliceSecret := alice.ComputeSecret(bob.PublicKey)
	bobSecret := bob.ComputeSecret(alice.PublicKey)
	
	fmt.Println(reflect.DeepEqual(aliceSecret, bobSecret)) // true
}
```

Example using different groups:
```go
package main

import (
	"fmt"
	"reflect"
	"github.com/WolframAlph/dh"
)
    
func main() {
	alice := dh.New(15)
	bob := dh.New(18)
	
	aliceSecret := alice.ComputeSecret(bob.PublicKey)
	bobSecret := bob.ComputeSecret(alice.PublicKey)
	
	fmt.Println(reflect.DeepEqual(aliceSecret, bobSecret)) // false
}
```
