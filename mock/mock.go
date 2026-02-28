package mock

import (
	"context"
	"sync"

	"github.com/zoth-iam/zoth/zlink"
)

type Call struct {
	Method string
	Args   []interface{}
}

type Connector struct {
	mu    sync.Mutex
	Calls []Call

	GrantFn       func(ctx context.Context, user zlink.UserIdentity, resource zlink.Resource, level zlink.AccessLevel) (*zlink.GrantResult, error)
	RevokeFn      func(ctx context.Context, user zlink.UserIdentity, resource zlink.Resource) (*zlink.RevokeResult, error)
	DiscoverFn    func(ctx context.Context, opts zlink.DiscoverOpts) (*zlink.DiscoverPage, error)
	CheckAccessFn func(ctx context.Context, user zlink.UserIdentity, resource zlink.Resource) (*zlink.AccessState, error)
	ResolveUserFn func(ctx context.Context, email string) (*zlink.UserIdentity, error)

	PlatformValue     zlink.Platform
	CapabilitiesValue zlink.Capabilities
}

func NewConnector(platform zlink.Platform) *Connector {
	return &Connector{
		PlatformValue: platform,
		CapabilitiesValue: zlink.Capabilities{
			CanGrant:       true,
			CanRevoke:      true,
			CanDiscover:    true,
			CanCheckAccess: true,
			CanResolveUser: true,
		},
	}
}

func (m *Connector) record(method string, args ...interface{}) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Calls = append(m.Calls, Call{Method: method, Args: args})
}

func (m *Connector) Platform() zlink.Platform {
	return m.PlatformValue
}

func (m *Connector) Capabilities() zlink.Capabilities {
	return m.CapabilitiesValue
}

func (m *Connector) Grant(ctx context.Context, user zlink.UserIdentity, resource zlink.Resource, level zlink.AccessLevel) (*zlink.GrantResult, error) {
	m.record("Grant", user, resource, level)
	if m.GrantFn != nil {
		return m.GrantFn(ctx, user, resource, level)
	}
	return &zlink.GrantResult{Success: true, Message: "mock grant"}, nil
}

func (m *Connector) Revoke(ctx context.Context, user zlink.UserIdentity, resource zlink.Resource) (*zlink.RevokeResult, error) {
	m.record("Revoke", user, resource)
	if m.RevokeFn != nil {
		return m.RevokeFn(ctx, user, resource)
	}
	return &zlink.RevokeResult{Success: true, Message: "mock revoke"}, nil
}

func (m *Connector) Discover(ctx context.Context, opts zlink.DiscoverOpts) (*zlink.DiscoverPage, error) {
	m.record("Discover", opts)
	if m.DiscoverFn != nil {
		return m.DiscoverFn(ctx, opts)
	}
	return &zlink.DiscoverPage{}, nil
}

func (m *Connector) CheckAccess(ctx context.Context, user zlink.UserIdentity, resource zlink.Resource) (*zlink.AccessState, error) {
	m.record("CheckAccess", user, resource)
	if m.CheckAccessFn != nil {
		return m.CheckAccessFn(ctx, user, resource)
	}
	return &zlink.AccessState{HasAccess: false}, nil
}

func (m *Connector) ResolveUser(ctx context.Context, email string) (*zlink.UserIdentity, error) {
	m.record("ResolveUser", email)
	if m.ResolveUserFn != nil {
		return m.ResolveUserFn(ctx, email)
	}
	return &zlink.UserIdentity{Email: email}, nil
}
