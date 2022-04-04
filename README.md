# dh

dh is a simple, ready to use Diffie-Hellman-Ephemeral implementation written in golang 
using MODP groups as defined in [RFC3526](https://datatracker.ietf.org/doc/html/rfc3526).

Example:

```Go
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
	
	fmt.Println(reflect.DeepEqual(aliceSecret, bobSecret))
}
```

## Notes

1. You must use the same MODP group on both sides, or else you
   end up with non-matching keys. Group #14 is used by default.
