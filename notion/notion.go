package notion

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/zoth-iam/zoth/zlink"
)

type notionSearchAPI interface {
	Search(ctx context.Context, query string, startCursor string, pageSize int) (*searchResult, error)
}

type searchResult struct {
	Results    []searchObject
	HasMore    bool
	NextCursor string
}

type searchObject struct {
	ID    string
	Type  string // "page" or "database"
	Title string
}

type scimAPI interface {
	FindUserByEmail(ctx context.Context, email string) (*scimUser, error)
	CreateUser(ctx context.Context, email, givenName, familyName string) (*scimUser, error)
	DeleteUser(ctx context.Context, userID string) error
	AddUserToGroup(ctx context.Context, groupID, userID string) error
	RemoveUserFromGroup(ctx context.Context, groupID, userID string) error
}

type connector struct {
	search notionSearchAPI
	scim   scimAPI
}

func New(cfg Config, opts ...zlink.Option) *connector {
	o := zlink.ApplyOptions(opts...)
	httpClient := o.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{}
	}

	return &connector{
		search: &notionSDKSearch{
			token:      cfg.IntegrationToken,
			httpClient: httpClient,
		},
		scim: newSCIMClient(cfg.SCIMToken, httpClient, ""),
	}
}

func newWithAPIs(search notionSearchAPI, scim scimAPI) *connector {
	return &connector{search: search, scim: scim}
}

func (c *connector) Platform() zlink.Platform {
	return zlink.Notion
}

func (c *connector) Capabilities() zlink.Capabilities {
	return zlink.Capabilities{
		CanGrant:       true,
		CanRevoke:      true,
		CanDiscover:    true,
		CanCheckAccess: false,
		CanResolveUser: true,
	}
}

func (c *connector) Grant(ctx context.Context, user zlink.UserIdentity, resource zlink.Resource, _ zlink.AccessLevel) (*zlink.GrantResult, error) {
	scimUserID, err := c.resolveScimUserID(ctx, user)
	if err != nil {
		return nil, err
	}

	groupID := resource.ExternalID
	if resource.Type == "workspace" {
		return nil, &zlink.Error{
			Kind:     zlink.ErrUnsupported,
			Platform: zlink.Notion,
			Op:       "grant",
			Message:  "workspace-level grant requires SCIM group ID in resource.ExternalID",
		}
	}

	if err := c.scim.AddUserToGroup(ctx, groupID, scimUserID); err != nil {
		return nil, classifyError(err, "grant")
	}

	return &zlink.GrantResult{
		Success: true,
		Message: fmt.Sprintf("added user %s to group %s", scimUserID, groupID),
		GrantID: fmt.Sprintf("%s:%s", groupID, scimUserID),
	}, nil
}

func (c *connector) Revoke(ctx context.Context, user zlink.UserIdentity, resource zlink.Resource) (*zlink.RevokeResult, error) {
	scimUserID, err := c.resolveScimUserID(ctx, user)
	if err != nil {
		return nil, err
	}

	groupID := resource.ExternalID
	if err := c.scim.RemoveUserFromGroup(ctx, groupID, scimUserID); err != nil {
		return nil, classifyError(err, "revoke")
	}

	return &zlink.RevokeResult{
		Success: true,
		Message: fmt.Sprintf("removed user %s from group %s", scimUserID, groupID),
	}, nil
}

func (c *connector) Discover(ctx context.Context, opts zlink.DiscoverOpts) (*zlink.DiscoverPage, error) {
	pageSize := opts.PageSize
	if pageSize <= 0 {
		pageSize = 20
	}

	result, err := c.search.Search(ctx, "", opts.PageToken, pageSize)
	if err != nil {
		return nil, classifyError(err, "discover")
	}

	resources := make([]zlink.Resource, 0, len(result.Results))
	for _, obj := range result.Results {
		resources = append(resources, zlink.Resource{
			ExternalID: obj.ID,
			Name:       obj.Title,
			Type:       obj.Type,
		})
	}

	nextToken := ""
	if result.HasMore {
		nextToken = result.NextCursor
	}

	return &zlink.DiscoverPage{
		Resources:     resources,
		NextPageToken: nextToken,
	}, nil
}

func (c *connector) CheckAccess(_ context.Context, _ zlink.UserIdentity, _ zlink.Resource) (*zlink.AccessState, error) {
	return nil, &zlink.Error{
		Kind:     zlink.ErrUnsupported,
		Platform: zlink.Notion,
		Op:       "check_access",
		Message:  "Notion does not support per-user access checking via API",
	}
}

func (c *connector) ResolveUser(ctx context.Context, email string) (*zlink.UserIdentity, error) {
	user, err := c.scim.FindUserByEmail(ctx, email)
	if err != nil {
		return nil, classifyError(err, "resolve_user")
	}
	if user == nil {
		return nil, &zlink.Error{
			Kind:     zlink.ErrNotFound,
			Platform: zlink.Notion,
			Op:       "resolve_user",
			Message:  fmt.Sprintf("no Notion user found for email %s", email),
		}
	}

	return &zlink.UserIdentity{
		Email: email,
		Metadata: map[string]string{
			"notion_scim_id": user.ID,
		},
	}, nil
}

func (c *connector) resolveScimUserID(ctx context.Context, user zlink.UserIdentity) (string, error) {
	if id, ok := user.Metadata["notion_scim_id"]; ok && id != "" {
		return id, nil
	}
	resolved, err := c.ResolveUser(ctx, user.Email)
	if err != nil {
		return "", err
	}
	return resolved.Metadata["notion_scim_id"], nil
}

type notionSDKSearch struct {
	token      string
	httpClient *http.Client
}

func (n *notionSDKSearch) Search(ctx context.Context, query string, startCursor string, pageSize int) (*searchResult, error) {
	body := map[string]interface{}{
		"page_size": pageSize,
	}
	if query != "" {
		body["query"] = query
	}
	if startCursor != "" {
		body["start_cursor"] = startCursor
	}

	return doNotionSearch(ctx, n.httpClient, n.token, body)
}

func classifyError(err error, op string) *zlink.Error {
	e := &zlink.Error{
		Kind:     zlink.ErrPlatform,
		Platform: zlink.Notion,
		Op:       op,
		Message:  err.Error(),
		Cause:    err,
	}

	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "401") || strings.Contains(msg, "unauthorized"):
		e.Kind = zlink.ErrAuth
	case strings.Contains(msg, "403") || strings.Contains(msg, "forbidden"):
		e.Kind = zlink.ErrPermission
	case strings.Contains(msg, "404") || strings.Contains(msg, "not found"):
		e.Kind = zlink.ErrNotFound
	case strings.Contains(msg, "409") || strings.Contains(msg, "conflict"):
		e.Kind = zlink.ErrConflict
	case strings.Contains(msg, "429") || strings.Contains(msg, "rate limit"):
		e.Kind = zlink.ErrRateLimit
	}

	return e
}
