package zlink

import "fmt"

type ErrorKind int

const (
	ErrAuth        ErrorKind = iota // credential issues
	ErrNotFound                     // resource or user not found
	ErrConflict                     // grant already exists, etc.
	ErrRateLimit                    // rate limited by platform
	ErrUnsupported                  // operation not supported by platform
	ErrPermission                   // insufficient permissions on the platform
	ErrPlatform                     // unexpected platform error
)

var errorKindNames = map[ErrorKind]string{
	ErrAuth:        "auth",
	ErrNotFound:    "not_found",
	ErrConflict:    "conflict",
	ErrRateLimit:   "rate_limit",
	ErrUnsupported: "unsupported",
	ErrPermission:  "permission",
	ErrPlatform:    "platform",
}

func (k ErrorKind) String() string {
	if s, ok := errorKindNames[k]; ok {
		return s
	}
	return fmt.Sprintf("unknown(%d)", int(k))
}

type Error struct {
	Kind     ErrorKind
	Platform Platform
	Op       string
	Message  string
	Cause    error
}

func (e *Error) Error() string {
	s := fmt.Sprintf("zlink[%s/%s]: %s: %s", e.Platform, e.Op, e.Kind, e.Message)
	if e.Cause != nil {
		s += ": " + e.Cause.Error()
	}
	return s
}

func (e *Error) Unwrap() error {
	return e.Cause
}
