package zlink

import (
	"context"
	"fmt"
	"sync"
)

type Platform string

const (
	GitHub Platform = "github"
	Azure  Platform = "azure"
	Notion Platform = "notion"
)

type AccessLevel string

const (
	AccessRead   AccessLevel = "read"
	AccessWrite  AccessLevel = "write"
	AccessAdmin  AccessLevel = "admin"
	AccessMember AccessLevel = "member"
	AccessCustom AccessLevel = "custom"
)

type Resource struct {
	ExternalID string
	Name       string
	Type       string
	Metadata   map[string]string
}

type UserIdentity struct {
	Email    string
	Metadata map[string]string
}

type GrantResult struct {
	Success bool
	Message string
	GrantID string
}

type RevokeResult struct {
	Success bool
	Message string
}

type AccessState struct {
	HasAccess bool
	Role      string
	GrantID   string
}

type Connector interface {
	Grant(ctx context.Context, user UserIdentity, resource Resource, level AccessLevel) (*GrantResult, error)
	Revoke(ctx context.Context, user UserIdentity, resource Resource) (*RevokeResult, error)
	Discover(ctx context.Context, opts DiscoverOpts) (*DiscoverPage, error)
	CheckAccess(ctx context.Context, user UserIdentity, resource Resource) (*AccessState, error)
	ResolveUser(ctx context.Context, email string) (*UserIdentity, error)
	Platform() Platform
	Capabilities() Capabilities
}

type Capabilities struct {
	CanGrant       bool
	CanRevoke      bool
	CanDiscover    bool
	CanCheckAccess bool
	CanResolveUser bool
}

type DiscoverOpts struct {
	ResourceType string
	PageSize     int
	PageToken    string
}

type DiscoverPage struct {
	Resources     []Resource
	NextPageToken string
}

type Registry struct {
	mu         sync.RWMutex
	connectors map[Platform]Connector
}

func NewRegistry() *Registry {
	return &Registry{
		connectors: make(map[Platform]Connector),
	}
}

func (r *Registry) Register(c Connector) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.connectors[c.Platform()] = c
}

func (r *Registry) Get(p Platform) (Connector, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	c, ok := r.connectors[p]
	if !ok {
		return nil, fmt.Errorf("zlink: no connector registered for platform %q", p)
	}
	return c, nil
}

func (r *Registry) Grant(ctx context.Context, platform Platform, user UserIdentity, resource Resource, level AccessLevel) (*GrantResult, error) {
	c, err := r.Get(platform)
	if err != nil {
		return nil, err
	}
	return c.Grant(ctx, user, resource, level)
}

func (r *Registry) Revoke(ctx context.Context, platform Platform, user UserIdentity, resource Resource) (*RevokeResult, error) {
	c, err := r.Get(platform)
	if err != nil {
		return nil, err
	}
	return c.Revoke(ctx, user, resource)
}

func (r *Registry) Discover(ctx context.Context, platform Platform, opts DiscoverOpts) (*DiscoverPage, error) {
	c, err := r.Get(platform)
	if err != nil {
		return nil, err
	}
	return c.Discover(ctx, opts)
}

func (r *Registry) CheckAccess(ctx context.Context, platform Platform, user UserIdentity, resource Resource) (*AccessState, error) {
	c, err := r.Get(platform)
	if err != nil {
		return nil, err
	}
	return c.CheckAccess(ctx, user, resource)
}

func (r *Registry) ResolveUser(ctx context.Context, platform Platform, email string) (*UserIdentity, error) {
	c, err := r.Get(platform)
	if err != nil {
		return nil, err
	}
	return c.ResolveUser(ctx, email)
}
