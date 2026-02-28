package azure

import (
	"fmt"

	"github.com/zoth-iam/zoth/zlink"
)

var roleDefinitionIDs = map[zlink.AccessLevel]string{
	zlink.AccessRead:  "acdd72a7-3385-48ef-bd42-f606fba81ae7", // Reader
	zlink.AccessWrite: "b24988ac-6180-42a0-ab88-20f7382dd24c", // Contributor
	zlink.AccessAdmin: "8e3af657-a8ff-443c-a75c-2fe8c4bcb635", // Owner
}

func roleDefinitionID(level zlink.AccessLevel, metadata map[string]string) (string, error) {
	if level == zlink.AccessCustom {
		id, ok := metadata["azure_role_definition_id"]
		if !ok || id == "" {
			return "", fmt.Errorf("custom access level requires azure_role_definition_id in resource metadata")
		}
		return id, nil
	}
	id, ok := roleDefinitionIDs[level]
	if !ok {
		return "", fmt.Errorf("unsupported access level: %s", level)
	}
	return id, nil
}

func fullRoleDefinitionID(subscriptionID, roleDefID string) string {
	return fmt.Sprintf("/subscriptions/%s/providers/Microsoft.Authorization/roleDefinitions/%s", subscriptionID, roleDefID)
}
