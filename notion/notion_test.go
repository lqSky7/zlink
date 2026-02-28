package notion

import (
	"context"
	"errors"
	"testing"

	"github.com/zoth-iam/zoth/zlink"
)

type mockSearch struct {
	search func(ctx context.Context, query string, startCursor string, pageSize int) (*searchResult, error)
}

func (m *mockSearch) Search(ctx context.Context, query string, startCursor string, pageSize int) (*searchResult, error) {
	return m.search(ctx, query, startCursor, pageSize)
}

type mockSCIM struct {
	findUserByEmail     func(ctx context.Context, email string) (*scimUser, error)
	createUser          func(ctx context.Context, email, givenName, familyName string) (*scimUser, error)
	deleteUser          func(ctx context.Context, userID string) error
	addUserToGroup      func(ctx context.Context, groupID, userID string) error
	removeUserFromGroup func(ctx context.Context, groupID, userID string) error
}

func (m *mockSCIM) FindUserByEmail(ctx context.Context, email string) (*scimUser, error) {
	return m.findUserByEmail(ctx, email)
}

func (m *mockSCIM) CreateUser(ctx context.Context, email, givenName, familyName string) (*scimUser, error) {
	return m.createUser(ctx, email, givenName, familyName)
}

func (m *mockSCIM) DeleteUser(ctx context.Context, userID string) error {
	return m.deleteUser(ctx, userID)
}

func (m *mockSCIM) AddUserToGroup(ctx context.Context, groupID, userID string) error {
	return m.addUserToGroup(ctx, groupID, userID)
}

func (m *mockSCIM) RemoveUserFromGroup(ctx context.Context, groupID, userID string) error {
	return m.removeUserFromGroup(ctx, groupID, userID)
}

func TestGrant_Happy(t *testing.T) {
	scim := &mockSCIM{
		addUserToGroup: func(_ context.Context, groupID, userID string) error {
			if groupID != "group-1" || userID != "scim-user-1" {
				t.Fatalf("unexpected args: group=%s user=%s", groupID, userID)
			}
			return nil
		},
	}

	c := newWithAPIs(nil, scim)
	result, err := c.Grant(context.Background(), zlink.UserIdentity{
		Email:    "alice@example.com",
		Metadata: map[string]string{"notion_scim_id": "scim-user-1"},
	}, zlink.Resource{ExternalID: "group-1", Type: "group"}, zlink.AccessMember)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Fatal("expected success")
	}
}

func TestGrant_AuthFail(t *testing.T) {
	scim := &mockSCIM{
		addUserToGroup: func(_ context.Context, _, _ string) error {
			return errors.New("401 unauthorized")
		},
	}

	c := newWithAPIs(nil, scim)
	_, err := c.Grant(context.Background(), zlink.UserIdentity{
		Email:    "alice@example.com",
		Metadata: map[string]string{"notion_scim_id": "scim-user-1"},
	}, zlink.Resource{ExternalID: "group-1", Type: "group"}, zlink.AccessMember)

	var zlinkErr *zlink.Error
	if !errors.As(err, &zlinkErr) {
		t.Fatalf("expected *zlink.Error, got %T", err)
	}
	if zlinkErr.Kind != zlink.ErrAuth {
		t.Fatalf("expected ErrAuth, got %s", zlinkErr.Kind)
	}
}

func TestRevoke_Happy(t *testing.T) {
	scim := &mockSCIM{
		removeUserFromGroup: func(_ context.Context, groupID, userID string) error {
			if groupID != "group-1" || userID != "scim-user-1" {
				t.Fatalf("unexpected args: group=%s user=%s", groupID, userID)
			}
			return nil
		},
	}

	c := newWithAPIs(nil, scim)
	result, err := c.Revoke(context.Background(), zlink.UserIdentity{
		Email:    "alice@example.com",
		Metadata: map[string]string{"notion_scim_id": "scim-user-1"},
	}, zlink.Resource{ExternalID: "group-1"})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Fatal("expected success")
	}
}

func TestRevoke_NotFound(t *testing.T) {
	scim := &mockSCIM{
		removeUserFromGroup: func(_ context.Context, _, _ string) error {
			return errors.New("404 not found")
		},
	}

	c := newWithAPIs(nil, scim)
	_, err := c.Revoke(context.Background(), zlink.UserIdentity{
		Email:    "alice@example.com",
		Metadata: map[string]string{"notion_scim_id": "scim-user-1"},
	}, zlink.Resource{ExternalID: "group-1"})

	var zlinkErr *zlink.Error
	if !errors.As(err, &zlinkErr) {
		t.Fatalf("expected *zlink.Error, got %T", err)
	}
	if zlinkErr.Kind != zlink.ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %s", zlinkErr.Kind)
	}
}

func TestDiscover_Pagination(t *testing.T) {
	search := &mockSearch{
		search: func(_ context.Context, _ string, cursor string, _ int) (*searchResult, error) {
			if cursor == "" {
				return &searchResult{
					Results: []searchObject{
						{ID: "page-1", Type: "page", Title: "Page One"},
						{ID: "page-2", Type: "page", Title: "Page Two"},
					},
					HasMore:    true,
					NextCursor: "cursor-abc",
				}, nil
			}
			return &searchResult{
				Results: []searchObject{
					{ID: "db-1", Type: "database", Title: "Database One"},
				},
				HasMore: false,
			}, nil
		},
	}

	c := newWithAPIs(search, nil)

	page1, err := c.Discover(context.Background(), zlink.DiscoverOpts{PageSize: 2})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(page1.Resources) != 2 {
		t.Fatalf("expected 2 resources, got %d", len(page1.Resources))
	}
	if page1.NextPageToken != "cursor-abc" {
		t.Fatalf("expected next token cursor-abc, got %s", page1.NextPageToken)
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

func TestCheckAccess_Unsupported(t *testing.T) {
	c := newWithAPIs(nil, nil)
	_, err := c.CheckAccess(context.Background(), zlink.UserIdentity{}, zlink.Resource{})

	var zlinkErr *zlink.Error
	if !errors.As(err, &zlinkErr) {
		t.Fatalf("expected *zlink.Error, got %T", err)
	}
	if zlinkErr.Kind != zlink.ErrUnsupported {
		t.Fatalf("expected ErrUnsupported, got %s", zlinkErr.Kind)
	}
}

func TestResolveUser_Found(t *testing.T) {
	scim := &mockSCIM{
		findUserByEmail: func(_ context.Context, email string) (*scimUser, error) {
			if email == "alice@example.com" {
				return &scimUser{ID: "scim-user-1", UserName: "alice@example.com"}, nil
			}
			return nil, nil
		},
	}

	c := newWithAPIs(nil, scim)
	identity, err := c.ResolveUser(context.Background(), "alice@example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if identity.Metadata["notion_scim_id"] != "scim-user-1" {
		t.Fatalf("expected scim-user-1, got %s", identity.Metadata["notion_scim_id"])
	}
}

func TestResolveUser_NotFound(t *testing.T) {
	scim := &mockSCIM{
		findUserByEmail: func(_ context.Context, _ string) (*scimUser, error) {
			return nil, nil
		},
	}

	c := newWithAPIs(nil, scim)
	_, err := c.ResolveUser(context.Background(), "nobody@example.com")

	var zlinkErr *zlink.Error
	if !errors.As(err, &zlinkErr) {
		t.Fatalf("expected *zlink.Error, got %T", err)
	}
	if zlinkErr.Kind != zlink.ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %s", zlinkErr.Kind)
	}
}
