package dirscan

import "errors"

// ErrNoValidHTTPResponse indicates no valid HTTP responses were received in a scan.
var ErrNoValidHTTPResponse = errors.New("No Valid HTTP response received")
