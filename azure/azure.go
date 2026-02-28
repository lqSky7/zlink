package azure

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/zoth-iam/zoth/zlink"
)

type rbacAPI interface {
	CreateRoleAssignment(ctx context.Context, scope, roleAssignmentName string, principalID, roleDefID string) (string, error)
	DeleteRoleAssignment(ctx context.Context, scope, roleAssignmentName string) error
	ListRoleAssignments(ctx context.Context, scope string, principalID string) ([]roleAssignment, error)
}

type roleAssignment struct {
	ID               string
	PrincipalID      string
	RoleDefinitionID string
	Scope            string
}

type graphAPI interface {
	GetUserByEmail(ctx context.Context, email string) (string, error) // returns object ID
}

type connector struct {
	rbac           rbacAPI
	graph          graphAPI
	subscriptionID string
}

func New(cfg Config, rbac rbacAPI, graph graphAPI) *connector {
	return &connector{
		rbac:           rbac,
		graph:          graph,
		subscriptionID: cfg.SubscriptionID,
	}
}

func (c *connector) Platform() zlink.Platform {
	return zlink.Azure
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
	principalID, err := c.resolvePrincipalID(ctx, user)
	if err != nil {
		return nil, err
	}

	roleDefID, err := roleDefinitionID(level, resource.Metadata)
	if err != nil {
		return nil, &zlink.Error{
			Kind:     zlink.ErrPlatform,
			Platform: zlink.Azure,
			Op:       "grant",
			Message:  err.Error(),
		}
	}

	fullRoleDefID := fullRoleDefinitionID(c.subscriptionID, roleDefID)
	assignmentName := uuid.New().String()

	name, rbacErr := c.rbac.CreateRoleAssignment(ctx, resource.ExternalID, assignmentName, principalID, fullRoleDefID)
	if rbacErr != nil {
		return nil, classifyError(rbacErr, "grant")
	}

	return &zlink.GrantResult{
		Success: true,
		Message: fmt.Sprintf("assigned role %s to %s on %s", roleDefID, principalID, resource.ExternalID),
		GrantID: name,
	}, nil
}

func (c *connector) Revoke(ctx context.Context, user zlink.UserIdentity, resource zlink.Resource) (*zlink.RevokeResult, error) {
	principalID, err := c.resolvePrincipalID(ctx, user)
	if err != nil {
		return nil, err
	}

	assignments, err := c.rbac.ListRoleAssignments(ctx, resource.ExternalID, principalID)
	if err != nil {
		return nil, classifyError(err, "revoke")
	}

	if len(assignments) == 0 {
		return nil, &zlink.Error{
			Kind:     zlink.ErrNotFound,
			Platform: zlink.Azure,
			Op:       "revoke",
			Message:  fmt.Sprintf("no role assignments found for principal %s on %s", principalID, resource.ExternalID),
		}
	}

	for _, a := range assignments {
		if err := c.rbac.DeleteRoleAssignment(ctx, resource.ExternalID, a.ID); err != nil {
			return nil, classifyError(err, "revoke")
		}
	}

	return &zlink.RevokeResult{
		Success: true,
		Message: fmt.Sprintf("revoked %d role assignment(s) for %s on %s", len(assignments), principalID, resource.ExternalID),
	}, nil
}

func (c *connector) Discover(_ context.Context, _ zlink.DiscoverOpts) (*zlink.DiscoverPage, error) {
	return &zlink.DiscoverPage{
		Resources: []zlink.Resource{
			{
				ExternalID: fmt.Sprintf("/subscriptions/%s", c.subscriptionID),
				Name:       c.subscriptionID,
				Type:       "subscription",
			},
		},
	}, nil
}

func (c *connector) CheckAccess(ctx context.Context, user zlink.UserIdentity, resource zlink.Resource) (*zlink.AccessState, error) {
	principalID, err := c.resolvePrincipalID(ctx, user)
	if err != nil {
		return nil, err
	}

	assignments, err := c.rbac.ListRoleAssignments(ctx, resource.ExternalID, principalID)
	if err != nil {
		return nil, classifyError(err, "check_access")
	}

	if len(assignments) == 0 {
		return &zlink.AccessState{HasAccess: false}, nil
	}

	return &zlink.AccessState{
		HasAccess: true,
		Role:      assignments[0].RoleDefinitionID,
		GrantID:   assignments[0].ID,
	}, nil
}

func (c *connector) ResolveUser(ctx context.Context, email string) (*zlink.UserIdentity, error) {
	objectID, err := c.graph.GetUserByEmail(ctx, email)
	if err != nil {
		return nil, classifyError(err, "resolve_user")
	}
	return &zlink.UserIdentity{
		Email: email,
		Metadata: map[string]string{
			"azure_object_id": objectID,
		},
	}, nil
}

func (c *connector) resolvePrincipalID(ctx context.Context, user zlink.UserIdentity) (string, error) {
	if id, ok := user.Metadata["azure_object_id"]; ok && id != "" {
		return id, nil
	}
	resolved, err := c.ResolveUser(ctx, user.Email)
	if err != nil {
		return "", err
	}
	return resolved.Metadata["azure_object_id"], nil
}

func classifyError(err error, op string) *zlink.Error {
	e := &zlink.Error{
		Kind:     zlink.ErrPlatform,
		Platform: zlink.Azure,
		Op:       op,
		Message:  err.Error(),
		Cause:    err,
	}

	msg := err.Error()
	switch {
	case contains(msg, "401", "unauthorized"):
		e.Kind = zlink.ErrAuth
	case contains(msg, "403", "forbidden"):
		e.Kind = zlink.ErrPermission
	case contains(msg, "404", "not found"):
		e.Kind = zlink.ErrNotFound
	case contains(msg, "409", "conflict", "already exists"):
		e.Kind = zlink.ErrConflict
	case contains(msg, "429", "throttled"):
		e.Kind = zlink.ErrRateLimit
	}

	return e
}

func contains(s string, substrs ...string) bool {
	for _, sub := range substrs {
		if len(s) >= len(sub) {
			for i := 0; i <= len(s)-len(sub); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
		}
	}
	return false
}
