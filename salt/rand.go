package salt

import "crypto/rand"

// randRead is a variable so it can be replaced in tests.
var randRead = rand.Read
