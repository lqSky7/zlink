package zlink

import "net/http"

type Options struct {
	HTTPClient *http.Client
}

type Option func(*Options)

func WithHTTPClient(c *http.Client) Option {
	return func(o *Options) {
		o.HTTPClient = c
	}
}

func ApplyOptions(opts ...Option) Options {
	o := Options{}
	for _, fn := range opts {
		fn(&o)
	}
	return o
}
