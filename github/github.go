package github

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	gh "github.com/google/go-github/v83/github"
	"github.com/zoth-iam/zoth/zlink"
)

type githubAPI interface {
	AddCollaborator(ctx context.Context, owner, repo, user string, opts *gh.RepositoryAddCollaboratorOptions) (*gh.CollaboratorInvitation, *gh.Response, error)
	RemoveCollaborator(ctx context.Context, owner, repo, user string) (*gh.Response, error)
	IsCollaborator(ctx context.Context, owner, repo, user string) (bool, *gh.Response, error)
	ListByOrg(ctx context.Context, org string, opts *gh.RepositoryListByOrgOptions) ([]*gh.Repository, *gh.Response, error)
	SearchUsers(ctx context.Context, query string, opts *gh.SearchOptions) (*gh.UsersSearchResult, *gh.Response, error)
}

type sdkClient struct {
	repos  *gh.RepositoriesService
	search *gh.SearchService
}

func (s *sdkClient) AddCollaborator(ctx context.Context, owner, repo, user string, opts *gh.RepositoryAddCollaboratorOptions) (*gh.CollaboratorInvitation, *gh.Response, error) {
	return s.repos.AddCollaborator(ctx, owner, repo, user, opts)
}

func (s *sdkClient) RemoveCollaborator(ctx context.Context, owner, repo, user string) (*gh.Response, error) {
	return s.repos.RemoveCollaborator(ctx, owner, repo, user)
}

func (s *sdkClient) IsCollaborator(ctx context.Context, owner, repo, user string) (bool, *gh.Response, error) {
	return s.repos.IsCollaborator(ctx, owner, repo, user)
}

func (s *sdkClient) ListByOrg(ctx context.Context, org string, opts *gh.RepositoryListByOrgOptions) ([]*gh.Repository, *gh.Response, error) {
	return s.repos.ListByOrg(ctx, org, opts)
}

func (s *sdkClient) SearchUsers(ctx context.Context, query string, opts *gh.SearchOptions) (*gh.UsersSearchResult, *gh.Response, error) {
	return s.search.Users(ctx, query, opts)
}

type connector struct {
	api   githubAPI
	owner string
}

func New(cfg Config, opts ...zlink.Option) *connector {
	o := zlink.ApplyOptions(opts...)
	httpClient := o.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{}
	}
	httpClient.Transport = &tokenTransport{
		token: cfg.Token,
		base:  httpClient.Transport,
	}
	client := gh.NewClient(httpClient)
	return &connector{
		api: &sdkClient{
			repos:  client.Repositories,
			search: client.Search,
		},
		owner: cfg.Owner,
	}
}

func newWithAPI(api githubAPI, owner string) *connector {
	return &connector{api: api, owner: owner}
}

type tokenTransport struct {
	token string
	base  http.RoundTripper
}

func (t *tokenTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	r := req.Clone(req.Context())
	r.Header.Set("Authorization", "Bearer "+t.token)
	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	return base.RoundTrip(r)
}

func (c *connector) Platform() zlink.Platform {
	return zlink.GitHub
}

func (c *connector) Capabilities() zlink.Capabilities {
	return zlink.Capabilities{
		CanGrant:       true,
		CanRevoke:      true,
		CanDiscover:    true,
		CanCheckAccess: true,
		CanResolveUser: true,
	}
}

func (c *connector) Grant(ctx context.Context, user zlink.UserIdentity, resource zlink.Resource, level zlink.AccessLevel) (*zlink.GrantResult, error) {
	username, err := c.resolveUsername(ctx, user)
	if err != nil {
		return nil, err
	}

	perm := mapPermission(level)
	inv, _, ghErr := c.api.AddCollaborator(ctx, c.owner, resource.ExternalID, username, &gh.RepositoryAddCollaboratorOptions{
		Permission: perm,
	})
	if ghErr != nil {
		return nil, classifyError(ghErr, "grant")
	}

	grantID := ""
	if inv != nil && inv.ID != nil {
		grantID = fmt.Sprintf("%d", *inv.ID)
	}

	return &zlink.GrantResult{
		Success: true,
		Message: fmt.Sprintf("granted %s access to %s/%s for %s", perm, c.owner, resource.ExternalID, username),
		GrantID: grantID,
	}, nil
}

func (c *connector) Revoke(ctx context.Context, user zlink.UserIdentity, resource zlink.Resource) (*zlink.RevokeResult, error) {
	username, err := c.resolveUsername(ctx, user)
	if err != nil {
		return nil, err
	}

	_, ghErr := c.api.RemoveCollaborator(ctx, c.owner, resource.ExternalID, username)
	if ghErr != nil {
		return nil, classifyError(ghErr, "revoke")
	}

	return &zlink.RevokeResult{
		Success: true,
		Message: fmt.Sprintf("revoked access to %s/%s for %s", c.owner, resource.ExternalID, username),
	}, nil
}

func (c *connector) Discover(ctx context.Context, opts zlink.DiscoverOpts) (*zlink.DiscoverPage, error) {
	page := 1
	if opts.PageToken != "" {
		if _, err := fmt.Sscanf(opts.PageToken, "%d", &page); err != nil {
			page = 1
		}
	}
	perPage := opts.PageSize
	if perPage <= 0 {
		perPage = 30
	}

	repos, resp, err := c.api.ListByOrg(ctx, c.owner, &gh.RepositoryListByOrgOptions{
		ListOptions: gh.ListOptions{Page: page, PerPage: perPage},
	})
	if err != nil {
		return nil, classifyError(err, "discover")
	}

	resources := make([]zlink.Resource, 0, len(repos))
	for _, r := range repos {
		name := ""
		if r.Name != nil {
			name = *r.Name
		}
		fullName := ""
		if r.FullName != nil {
			fullName = *r.FullName
		}
		resources = append(resources, zlink.Resource{
			ExternalID: name,
			Name:       fullName,
			Type:       "repo",
		})
	}

	nextToken := ""
	if resp != nil && resp.NextPage != 0 {
		nextToken = fmt.Sprintf("%d", resp.NextPage)
	}

	return &zlink.DiscoverPage{
		Resources:     resources,
		NextPageToken: nextToken,
	}, nil
}

func (c *connector) CheckAccess(ctx context.Context, user zlink.UserIdentity, resource zlink.Resource) (*zlink.AccessState, error) {
	username, err := c.resolveUsername(ctx, user)
	if err != nil {
		return nil, err
	}

	isCollab, _, ghErr := c.api.IsCollaborator(ctx, c.owner, resource.ExternalID, username)
	if ghErr != nil {
		return nil, classifyError(ghErr, "check_access")
	}

	return &zlink.AccessState{
		HasAccess: isCollab,
	}, nil
}

func (c *connector) ResolveUser(ctx context.Context, email string) (*zlink.UserIdentity, error) {
	query := email + " in:email"
	result, _, err := c.api.SearchUsers(ctx, query, &gh.SearchOptions{
		ListOptions: gh.ListOptions{PerPage: 1},
	})
	if err != nil {
		return nil, classifyError(err, "resolve_user")
	}
	if result == nil || len(result.Users) == 0 {
		return nil, &zlink.Error{
			Kind:     zlink.ErrNotFound,
			Platform: zlink.GitHub,
			Op:       "resolve_user",
			Message:  fmt.Sprintf("no GitHub user found for email %s", email),
		}
	}

	u := result.Users[0]
	username := ""
	if u.Login != nil {
		username = *u.Login
	}

	return &zlink.UserIdentity{
		Email: email,
		Metadata: map[string]string{
			"github_username": username,
		},
	}, nil
}

func (c *connector) resolveUsername(ctx context.Context, user zlink.UserIdentity) (string, error) {
	if u, ok := user.Metadata["github_username"]; ok && u != "" {
		return u, nil
	}
	resolved, err := c.ResolveUser(ctx, user.Email)
	if err != nil {
		return "", err
	}
	return resolved.Metadata["github_username"], nil
}

func mapPermission(level zlink.AccessLevel) string {
	switch level {
	case zlink.AccessRead:
		return "pull"
	case zlink.AccessWrite:
		return "push"
	case zlink.AccessAdmin:
		return "admin"
	default:
		return "pull"
	}
}

func classifyError(err error, op string) *zlink.Error {
	e := &zlink.Error{
		Kind:     zlink.ErrPlatform,
		Platform: zlink.GitHub,
		Op:       op,
		Message:  err.Error(),
		Cause:    err,
	}

	errMsg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(errMsg, "401") || strings.Contains(errMsg, "bad credentials"):
		e.Kind = zlink.ErrAuth
	case strings.Contains(errMsg, "403"):
		if strings.Contains(errMsg, "rate limit") {
			e.Kind = zlink.ErrRateLimit
		} else {
			e.Kind = zlink.ErrPermission
		}
	case strings.Contains(errMsg, "404"):
		e.Kind = zlink.ErrNotFound
	case strings.Contains(errMsg, "409"):
		e.Kind = zlink.ErrConflict
	case strings.Contains(errMsg, "429"):
		e.Kind = zlink.ErrRateLimit
	}

	return e
}
