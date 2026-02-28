package github

import (
	"context"
	"errors"
	"testing"

	gh "github.com/google/go-github/v83/github"
	"github.com/zoth-iam/zoth/zlink"
)

type mockGitHubAPI struct {
	addCollaborator    func(ctx context.Context, owner, repo, user string, opts *gh.RepositoryAddCollaboratorOptions) (*gh.CollaboratorInvitation, *gh.Response, error)
	removeCollaborator func(ctx context.Context, owner, repo, user string) (*gh.Response, error)
	isCollaborator     func(ctx context.Context, owner, repo, user string) (bool, *gh.Response, error)
	listByOrg          func(ctx context.Context, org string, opts *gh.RepositoryListByOrgOptions) ([]*gh.Repository, *gh.Response, error)
	searchUsers        func(ctx context.Context, query string, opts *gh.SearchOptions) (*gh.UsersSearchResult, *gh.Response, error)
}

func (m *mockGitHubAPI) AddCollaborator(ctx context.Context, owner, repo, user string, opts *gh.RepositoryAddCollaboratorOptions) (*gh.CollaboratorInvitation, *gh.Response, error) {
	return m.addCollaborator(ctx, owner, repo, user, opts)
}

func (m *mockGitHubAPI) RemoveCollaborator(ctx context.Context, owner, repo, user string) (*gh.Response, error) {
	return m.removeCollaborator(ctx, owner, repo, user)
}

func (m *mockGitHubAPI) IsCollaborator(ctx context.Context, owner, repo, user string) (bool, *gh.Response, error) {
	return m.isCollaborator(ctx, owner, repo, user)
}

func (m *mockGitHubAPI) ListByOrg(ctx context.Context, org string, opts *gh.RepositoryListByOrgOptions) ([]*gh.Repository, *gh.Response, error) {
	return m.listByOrg(ctx, org, opts)
}

func (m *mockGitHubAPI) SearchUsers(ctx context.Context, query string, opts *gh.SearchOptions) (*gh.UsersSearchResult, *gh.Response, error) {
	return m.searchUsers(ctx, query, opts)
}

func ptr[T any](v T) *T { return &v }

func TestGrant_Happy(t *testing.T) {
	mock := &mockGitHubAPI{
		addCollaborator: func(_ context.Context, _, _, _ string, opts *gh.RepositoryAddCollaboratorOptions) (*gh.CollaboratorInvitation, *gh.Response, error) {
			if opts.Permission != "push" {
				t.Fatalf("expected permission push, got %s", opts.Permission)
			}
			return &gh.CollaboratorInvitation{ID: ptr(int64(42))}, nil, nil
		},
	}

	c := newWithAPI(mock, "test-org")
	result, err := c.Grant(context.Background(), zlink.UserIdentity{
		Email:    "alice@example.com",
		Metadata: map[string]string{"github_username": "alice"},
	}, zlink.Resource{ExternalID: "my-repo"}, zlink.AccessWrite)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Fatal("expected success")
	}
	if result.GrantID != "42" {
		t.Fatalf("expected grant ID 42, got %s", result.GrantID)
	}
}

func TestGrant_AuthFail(t *testing.T) {
	mock := &mockGitHubAPI{
		addCollaborator: func(_ context.Context, _, _, _ string, _ *gh.RepositoryAddCollaboratorOptions) (*gh.CollaboratorInvitation, *gh.Response, error) {
			return nil, nil, errors.New("401 Bad credentials")
		},
	}

	c := newWithAPI(mock, "test-org")
	_, err := c.Grant(context.Background(), zlink.UserIdentity{
		Email:    "alice@example.com",
		Metadata: map[string]string{"github_username": "alice"},
	}, zlink.Resource{ExternalID: "my-repo"}, zlink.AccessRead)

	var zlinkErr *zlink.Error
	if !errors.As(err, &zlinkErr) {
		t.Fatalf("expected *zlink.Error, got %T", err)
	}
	if zlinkErr.Kind != zlink.ErrAuth {
		t.Fatalf("expected ErrAuth, got %s", zlinkErr.Kind)
	}
}

func TestGrant_NotFound(t *testing.T) {
	mock := &mockGitHubAPI{
		addCollaborator: func(_ context.Context, _, _, _ string, _ *gh.RepositoryAddCollaboratorOptions) (*gh.CollaboratorInvitation, *gh.Response, error) {
			return nil, nil, errors.New("404 Not Found")
		},
	}

	c := newWithAPI(mock, "test-org")
	_, err := c.Grant(context.Background(), zlink.UserIdentity{
		Email:    "alice@example.com",
		Metadata: map[string]string{"github_username": "alice"},
	}, zlink.Resource{ExternalID: "nonexistent"}, zlink.AccessRead)

	var zlinkErr *zlink.Error
	if !errors.As(err, &zlinkErr) {
		t.Fatalf("expected *zlink.Error, got %T", err)
	}
	if zlinkErr.Kind != zlink.ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %s", zlinkErr.Kind)
	}
}

func TestRevoke_Happy(t *testing.T) {
	mock := &mockGitHubAPI{
		removeCollaborator: func(_ context.Context, _, _, _ string) (*gh.Response, error) {
			return nil, nil
		},
	}

	c := newWithAPI(mock, "test-org")
	result, err := c.Revoke(context.Background(), zlink.UserIdentity{
		Email:    "alice@example.com",
		Metadata: map[string]string{"github_username": "alice"},
	}, zlink.Resource{ExternalID: "my-repo"})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Fatal("expected success")
	}
}

func TestRevoke_NotFound(t *testing.T) {
	mock := &mockGitHubAPI{
		removeCollaborator: func(_ context.Context, _, _, _ string) (*gh.Response, error) {
			return nil, errors.New("404 Not Found")
		},
	}

	c := newWithAPI(mock, "test-org")
	_, err := c.Revoke(context.Background(), zlink.UserIdentity{
		Email:    "alice@example.com",
		Metadata: map[string]string{"github_username": "alice"},
	}, zlink.Resource{ExternalID: "nonexistent"})

	var zlinkErr *zlink.Error
	if !errors.As(err, &zlinkErr) {
		t.Fatalf("expected *zlink.Error, got %T", err)
	}
	if zlinkErr.Kind != zlink.ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %s", zlinkErr.Kind)
	}
}

func TestDiscover_Pagination(t *testing.T) {
	mock := &mockGitHubAPI{
		listByOrg: func(_ context.Context, _ string, opts *gh.RepositoryListByOrgOptions) ([]*gh.Repository, *gh.Response, error) {
			if opts.Page == 1 {
				return []*gh.Repository{
					{Name: ptr("repo-1"), FullName: ptr("org/repo-1")},
					{Name: ptr("repo-2"), FullName: ptr("org/repo-2")},
				}, &gh.Response{NextPage: 2}, nil
			}
			return []*gh.Repository{
				{Name: ptr("repo-3"), FullName: ptr("org/repo-3")},
			}, &gh.Response{NextPage: 0}, nil
		},
	}

	c := newWithAPI(mock, "test-org")

	page1, err := c.Discover(context.Background(), zlink.DiscoverOpts{PageSize: 2})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(page1.Resources) != 2 {
		t.Fatalf("expected 2 resources, got %d", len(page1.Resources))
	}
	if page1.NextPageToken != "2" {
		t.Fatalf("expected next token '2', got %s", page1.NextPageToken)
	}

	page2, err := c.Discover(context.Background(), zlink.DiscoverOpts{PageSize: 2, PageToken: page1.NextPageToken})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(page2.Resources) != 1 {
		t.Fatalf("expected 1 resource, got %d", len(page2.Resources))
	}
	if page2.NextPageToken != "" {
		t.Fatalf("expected empty next token, got %s", page2.NextPageToken)
	}
}

func TestCheckAccess_Yes(t *testing.T) {
	mock := &mockGitHubAPI{
		isCollaborator: func(_ context.Context, _, _, _ string) (bool, *gh.Response, error) {
			return true, nil, nil
		},
	}

	c := newWithAPI(mock, "test-org")
	state, err := c.CheckAccess(context.Background(), zlink.UserIdentity{
		Email:    "alice@example.com",
		Metadata: map[string]string{"github_username": "alice"},
	}, zlink.Resource{ExternalID: "my-repo"})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !state.HasAccess {
		t.Fatal("expected HasAccess true")
	}
}

func TestCheckAccess_No(t *testing.T) {
	mock := &mockGitHubAPI{
		isCollaborator: func(_ context.Context, _, _, _ string) (bool, *gh.Response, error) {
			return false, nil, nil
		},
	}

	c := newWithAPI(mock, "test-org")
	state, err := c.CheckAccess(context.Background(), zlink.UserIdentity{
		Email:    "alice@example.com",
		Metadata: map[string]string{"github_username": "alice"},
	}, zlink.Resource{ExternalID: "my-repo"})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if state.HasAccess {
		t.Fatal("expected HasAccess false")
	}
}

func TestResolveUser_Found(t *testing.T) {
	mock := &mockGitHubAPI{
		searchUsers: func(_ context.Context, _ string, _ *gh.SearchOptions) (*gh.UsersSearchResult, *gh.Response, error) {
			return &gh.UsersSearchResult{
				Users: []*gh.User{{Login: ptr("alice")}},
			}, nil, nil
		},
	}

	c := newWithAPI(mock, "test-org")
	identity, err := c.ResolveUser(context.Background(), "alice@example.com")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if identity.Metadata["github_username"] != "alice" {
		t.Fatalf("expected username alice, got %s", identity.Metadata["github_username"])
	}
}

func TestResolveUser_NotFound(t *testing.T) {
	mock := &mockGitHubAPI{
		searchUsers: func(_ context.Context, _ string, _ *gh.SearchOptions) (*gh.UsersSearchResult, *gh.Response, error) {
			return &gh.UsersSearchResult{Users: []*gh.User{}}, nil, nil
		},
	}

	c := newWithAPI(mock, "test-org")
	_, err := c.ResolveUser(context.Background(), "nobody@example.com")

	var zlinkErr *zlink.Error
	if !errors.As(err, &zlinkErr) {
		t.Fatalf("expected *zlink.Error, got %T", err)
	}
	if zlinkErr.Kind != zlink.ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %s", zlinkErr.Kind)
	}
}

func TestPermissionMapping(t *testing.T) {
	tests := []struct {
		level zlink.AccessLevel
		want  string
	}{
		{zlink.AccessRead, "pull"},
		{zlink.AccessWrite, "push"},
		{zlink.AccessAdmin, "admin"},
		{zlink.AccessMember, "pull"},
		{zlink.AccessCustom, "pull"},
	}
	for _, tt := range tests {
		got := mapPermission(tt.level)
		if got != tt.want {
			t.Errorf("mapPermission(%s) = %s, want %s", tt.level, got, tt.want)
		}
	}
}
