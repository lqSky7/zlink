package azure

import (
	"context"
	"errors"
	"testing"

	"github.com/zoth-iam/zoth/zlink"
)

type mockRBAC struct {
	createRoleAssignment func(ctx context.Context, scope, name, principalID, roleDefID string) (string, error)
	deleteRoleAssignment func(ctx context.Context, scope, name string) error
	listRoleAssignments  func(ctx context.Context, scope, principalID string) ([]roleAssignment, error)
}

func (m *mockRBAC) CreateRoleAssignment(ctx context.Context, scope, name, principalID, roleDefID string) (string, error) {
	return m.createRoleAssignment(ctx, scope, name, principalID, roleDefID)
}

func (m *mockRBAC) DeleteRoleAssignment(ctx context.Context, scope, name string) error {
	return m.deleteRoleAssignment(ctx, scope, name)
}

func (m *mockRBAC) ListRoleAssignments(ctx context.Context, scope, principalID string) ([]roleAssignment, error) {
	return m.listRoleAssignments(ctx, scope, principalID)
}

type mockGraph struct {
	getUserByEmail func(ctx context.Context, email string) (string, error)
}

func (m *mockGraph) GetUserByEmail(ctx context.Context, email string) (string, error) {
	return m.getUserByEmail(ctx, email)
}

func testConnector(rbac rbacAPI, graph graphAPI) *connector {
	return &connector{
		rbac:           rbac,
		graph:          graph,
		subscriptionID: "test-sub-id",
	}
}

func TestGrant_Happy(t *testing.T) {
	rbac := &mockRBAC{
		createRoleAssignment: func(_ context.Context, _, _, _, _ string) (string, error) {
			return "assignment-1", nil
		},
	}
	graph := &mockGraph{}
	c := testConnector(rbac, graph)

	result, err := c.Grant(context.Background(), zlink.UserIdentity{
		Email:    "alice@example.com",
		Metadata: map[string]string{"azure_object_id": "obj-123"},
	}, zlink.Resource{ExternalID: "/subscriptions/test/resourceGroups/rg1"}, zlink.AccessWrite)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Fatal("expected success")
	}
	if result.GrantID != "assignment-1" {
		t.Fatalf("expected grant ID assignment-1, got %s", result.GrantID)
	}
}

func TestGrant_Conflict(t *testing.T) {
	rbac := &mockRBAC{
		createRoleAssignment: func(_ context.Context, _, _, _, _ string) (string, error) {
			return "", errors.New("409 conflict: role assignment already exists")
		},
	}
	graph := &mockGraph{}
	c := testConnector(rbac, graph)

	_, err := c.Grant(context.Background(), zlink.UserIdentity{
		Email:    "alice@example.com",
		Metadata: map[string]string{"azure_object_id": "obj-123"},
	}, zlink.Resource{ExternalID: "/subscriptions/test/resourceGroups/rg1"}, zlink.AccessRead)

	var zlinkErr *zlink.Error
	if !errors.As(err, &zlinkErr) {
		t.Fatalf("expected *zlink.Error, got %T", err)
	}
	if zlinkErr.Kind != zlink.ErrConflict {
		t.Fatalf("expected ErrConflict, got %s", zlinkErr.Kind)
	}
}

func TestRevoke_Happy(t *testing.T) {
	rbac := &mockRBAC{
		listRoleAssignments: func(_ context.Context, _, _ string) ([]roleAssignment, error) {
			return []roleAssignment{{ID: "assign-1", PrincipalID: "obj-123"}}, nil
		},
		deleteRoleAssignment: func(_ context.Context, _, _ string) error {
			return nil
		},
	}
	graph := &mockGraph{}
	c := testConnector(rbac, graph)

	result, err := c.Revoke(context.Background(), zlink.UserIdentity{
		Email:    "alice@example.com",
		Metadata: map[string]string{"azure_object_id": "obj-123"},
	}, zlink.Resource{ExternalID: "/subscriptions/test/resourceGroups/rg1"})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Fatal("expected success")
	}
}

func TestRevoke_NotFound(t *testing.T) {
	rbac := &mockRBAC{
		listRoleAssignments: func(_ context.Context, _, _ string) ([]roleAssignment, error) {
			return []roleAssignment{}, nil
		},
	}
	graph := &mockGraph{}
	c := testConnector(rbac, graph)

	_, err := c.Revoke(context.Background(), zlink.UserIdentity{
		Email:    "alice@example.com",
		Metadata: map[string]string{"azure_object_id": "obj-123"},
	}, zlink.Resource{ExternalID: "/subscriptions/test/resourceGroups/rg1"})

	var zlinkErr *zlink.Error
	if !errors.As(err, &zlinkErr) {
		t.Fatalf("expected *zlink.Error, got %T", err)
	}
	if zlinkErr.Kind != zlink.ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %s", zlinkErr.Kind)
	}
}

func TestCheckAccess_HasAccess(t *testing.T) {
	rbac := &mockRBAC{
		listRoleAssignments: func(_ context.Context, _, _ string) ([]roleAssignment, error) {
			return []roleAssignment{{ID: "assign-1", PrincipalID: "obj-123", RoleDefinitionID: "reader-id"}}, nil
		},
	}
	graph := &mockGraph{}
	c := testConnector(rbac, graph)

	state, err := c.CheckAccess(context.Background(), zlink.UserIdentity{
		Email:    "alice@example.com",
		Metadata: map[string]string{"azure_object_id": "obj-123"},
	}, zlink.Resource{ExternalID: "/subscriptions/test/resourceGroups/rg1"})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !state.HasAccess {
		t.Fatal("expected HasAccess true")
	}
	if state.Role != "reader-id" {
		t.Fatalf("expected role reader-id, got %s", state.Role)
	}
}

func TestCheckAccess_NoAccess(t *testing.T) {
	rbac := &mockRBAC{
		listRoleAssignments: func(_ context.Context, _, _ string) ([]roleAssignment, error) {
			return []roleAssignment{}, nil
		},
	}
	graph := &mockGraph{}
	c := testConnector(rbac, graph)

	state, err := c.CheckAccess(context.Background(), zlink.UserIdentity{
		Email:    "alice@example.com",
		Metadata: map[string]string{"azure_object_id": "obj-123"},
	}, zlink.Resource{ExternalID: "/subscriptions/test/resourceGroups/rg1"})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if state.HasAccess {
		t.Fatal("expected HasAccess false")
	}
}

func TestResolveUser_Happy(t *testing.T) {
	graph := &mockGraph{
		getUserByEmail: func(_ context.Context, email string) (string, error) {
			if email == "alice@example.com" {
				return "obj-123", nil
			}
			return "", errors.New("404 not found")
		},
	}
	c := testConnector(nil, graph)

	identity, err := c.ResolveUser(context.Background(), "alice@example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if identity.Metadata["azure_object_id"] != "obj-123" {
		t.Fatalf("expected obj-123, got %s", identity.Metadata["azure_object_id"])
	}
}

func TestResolveUser_NotFound(t *testing.T) {
	graph := &mockGraph{
		getUserByEmail: func(_ context.Context, _ string) (string, error) {
			return "", errors.New("404 not found")
		},
	}
	c := testConnector(nil, graph)

	_, err := c.ResolveUser(context.Background(), "nobody@example.com")

	var zlinkErr *zlink.Error
	if !errors.As(err, &zlinkErr) {
		t.Fatalf("expected *zlink.Error, got %T", err)
	}
	if zlinkErr.Kind != zlink.ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %s", zlinkErr.Kind)
	}
}

func TestRoleMapping(t *testing.T) {
	tests := []struct {
		level   zlink.AccessLevel
		meta    map[string]string
		wantID  string
		wantErr bool
	}{
		{zlink.AccessRead, nil, "acdd72a7-3385-48ef-bd42-f606fba81ae7", false},
		{zlink.AccessWrite, nil, "b24988ac-6180-42a0-ab88-20f7382dd24c", false},
		{zlink.AccessAdmin, nil, "8e3af657-a8ff-443c-a75c-2fe8c4bcb635", false},
		{zlink.AccessCustom, map[string]string{"azure_role_definition_id": "custom-id"}, "custom-id", false},
		{zlink.AccessCustom, nil, "", true},
		{zlink.AccessMember, nil, "", true},
	}
	for _, tt := range tests {
		got, err := roleDefinitionID(tt.level, tt.meta)
		if tt.wantErr {
			if err == nil {
				t.Errorf("roleDefinitionID(%s) expected error, got nil", tt.level)
			}
			continue
		}
		if err != nil {
			t.Errorf("roleDefinitionID(%s) unexpected error: %v", tt.level, err)
			continue
		}
		if got != tt.wantID {
			t.Errorf("roleDefinitionID(%s) = %s, want %s", tt.level, got, tt.wantID)
		}
	}
}

func TestDiscover(t *testing.T) {
	c := testConnector(nil, nil)
	page, err := c.Discover(context.Background(), zlink.DiscoverOpts{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(page.Resources) != 1 {
		t.Fatalf("expected 1 resource, got %d", len(page.Resources))
	}
	if page.Resources[0].Type != "subscription" {
		t.Fatalf("expected type subscription, got %s", page.Resources[0].Type)
	}
}
