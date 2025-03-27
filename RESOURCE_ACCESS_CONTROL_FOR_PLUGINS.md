# **Resource Sharing and Access Control in OpenSearch**

This guide provides an **in-depth overview** for **plugin developers**, covering the **features, setup, and utilization** of the **Resource Sharing and Access Control** functionality in OpenSearch.

## **1. What is the Feature?**
The **Resource Sharing and Access Control** feature in OpenSearch Security Plugin enables fine-grained access management for resources declared by plugins. It allows:
- Users to **share and revoke access** to their own resources.
- **Super admins** to access all resources.
- Plugins to **define and manage resource access** via a standardized interface.

This feature ensures **secure** and **controlled** access to shareableResources while leveraging existing **index-level authorization** in OpenSearch.

---

## **2. What are the Components?**
This feature introduces **two primary components** for plugin developers:

### **1. `opensearch-security-client`**
- Provides a client with methods for **resource access control**.
- Plugins must declare a **dependency** on this client to integrate with security features.

### **2. `opensearch-resource-sharing-spi`**
- A **Service Provider Interface (SPI)** that plugins must implement to declare themselves as **Resource Plugins**.
- The security plugin keeps track of these plugins (similar to how JobScheduler tracks `JobSchedulerExtension`).

### **Plugin Implementation Requirements:**

- This feature is marked as **`@opensearch.experimental`** and can be toggled using the feature flag: **`plugins.security.resource_sharing.enabled`**, which is **enabled by default**.
- **Resource indices must be system indices**, and **system index protection must be enabled** (`plugins.security.system_indices.enabled: true`) to prevent unauthorized direct access.
- Plugins must declare dependencies on **`opensearch-security-client`** and **`opensearch-resource-sharing-spi`** in their `build.gradle`.

### **Plugin Implementation Requirements**
Each plugin must:
- **Declare a dependency** on `opensearch-security-client` package:
```build.gradle
implementation group: 'org.opensearch', name:'opensearch-security-client', version: "${opensearch_build}"
```
- **Declare a `compileOnly` dependency** on `opensearch-resource-sharing-spi` package:
```build.gradle
compileOnly group: 'org.opensearch', name:'opensearch-resource-sharing-spi', version:"${opensearch_build}"
```
- **Extend** `opensearch-security` plugin with optional flag:
```build.gradle
opensearchplugin {
    name '<your-plugin>'
    description '<description>'
    classname '<your-classpath>'
    extendedPlugins = ['opensearch-security;optional=true', <any-other-extensions>]
}
```
- **Implement** the `ResourceSharingExtension` class.
- **Ensure** that its declared resources implement the `Resource` interface.
- **Provide a resource parser**, which the security plugin uses to extract resource details from the resource index.
- **Register itself** in `META-INF/services` by creating the following file:
  ```
  src/main/resources/META-INF/services/org.opensearch.security.spi.ResourceSharingExtension
  ```
    - This file must contain a **single line** specifying the **fully qualified class name** of the plugin’s `ResourceSharingExtension` implementation, e.g.:
      ```
      org.opensearch.sample.SampleResourcePlugin
      ```
---

## **3. Feature Flag**
This feature is controlled by the following flag:

- **Feature flag:** `plugins.security.resource_sharing.enabled`
- **Default value:** `true`
- **How to disable?** Set the flag to `false` in the opensearch configuration:
  ```yaml
  plugins.security.resource_sharing.enabled: false
  ```

---

## **4. Declaring a Resource Plugin and Using the Client for Access Control**
### **Declaring a Plugin as a Resource Plugin**
To integrate with the security plugin, your plugin must:
1. Extend `ResourceSharingExtension` and implement required methods.
2. Implement the `ShareableResource` interface for resource declaration.
3. Implement a resource parser to extract resource details.

[`opensearch-resource-sharing-spi` README.md](./spi/README.md) is a great resource to learn more about the components of SPI and how to set up.

Tip: Refer to the `org.opensearch.sample.SampleResourcePlugin` class to understand the setup in further detail.

Example usage:
```java

public class SampleResourcePlugin extends Plugin implements SystemIndexPlugin, ResourceSharingExtension {

    // override any required methods

    @Override
    public Collection<SystemIndexDescriptor> getSystemIndexDescriptors(Settings settings) {
        final SystemIndexDescriptor systemIndexDescriptor = new SystemIndexDescriptor(RESOURCE_INDEX_NAME, "Sample index with resources");
        return Collections.singletonList(systemIndexDescriptor);
    }

    @Override
    public String getResourceType() {
        return SampleResource.class.getCanonicalName();
    }

    @Override
    public String getResourceIndex() {
        return RESOURCE_INDEX_NAME;
    }

    @Override
    public ShareableResourceParser<SampleResource> getResourceParser() {
        return new SampleResourceParser();
    }
}
```


### **Calling Access Control Methods from the ResourceSharingClient Client**
Plugins must **declare a dependency** on `opensearch-security-client` and use it to call access control methods.
The client provides **four access control methods** for plugins. For detailed usage and implementation, refer to the [`opensearch-security-client` README.md](./client/README.md)


Tip: Refer to the `org.opensearch.sample.resource.client.ResourceSharingClientAccessor` class to understand the client setup in further detail.

Example usage:
```java
 @Override
void doExecute(Task task, ShareResourceRequest request, ActionListener<ShareResourceResponse> listener) {
    if (request.getResourceId() == null || request.getResourceId().isEmpty()) {
        listener.onFailure(new IllegalArgumentException("Resource ID cannot be null or empty"));
        return;
    }

    ResourceSharingClient resourceSharingClient = ResourceSharingClientAccessor.getResourceSharingClient(nodeClient, settings);
    resourceSharingClient.shareResource(
            request.getResourceId(),
            RESOURCE_INDEX_NAME,
            request.getShareWith(),
            ActionListener.wrap(sharing -> {
                ShareResourceResponse response = new ShareResourceResponse(sharing.getShareWith());
                listener.onResponse(response);
            }, listener::onFailure)
    );
}
```


---

Here's a **cleaned-up and clarified version** of your README section, with redundancy removed, grammar improved, and examples aligned for consistency and clarity:

---

## **5. What are ActionGroups?**

This feature uses a **sharing mechanism** called **ActionGroups** to define the **level of access** granted to users for a resource. Currently, only one action group is available: `default`.

When sharing a resource, users must understand that access is tied to **API permissions**. For example, if a user has delete permissions, they can delete any resource shared with them.

By default, all `shareableResources` are private — visible only to their **owner** and **super-admins**. A resource becomes accessible to others only when explicitly shared.

> This mechanism will be more actively used once the Resource Authorization framework is implemented as a standalone feature.

### **Example: Publicly Shared Resource**

To make a resource accessible to everyone, share it with all entities using the wildcard `*`:

```json
{
  "share_with": {
    "default": {
      "backend_roles": ["*"],
      "roles": ["*"],
      "users": ["*"]
    }
  }
}
```

This grants access to:
- **All backend roles** via `"backend_roles": ["*"]`
- **All roles** via `"roles": ["*"]`
- **All users** via `"users": ["*"]`

**The resource becomes publicly accessible to all entities.**

### **Example: Restricted/Exclusively Shared Resource**

To restrict access to specific users, roles, or backend roles:

```json
{
  "share_with": {
    "default": {
      "backend_roles": ["backend_role1"],
      "roles": ["role1"],
      "users": ["user1"]
    }
  }
}
```

This grants access only to:
- Backend role: `backend_role1`
- Role: `role1`
- User: `user1`

**The resource is accessible only to the specified entities.**


### **Example: Private Resource**

To keep a resource fully private:

```json
{
  "share_with": {}
}
```

Since no entities are listed, the resource is accessible **only by its creator and super-admins**.

**This is the default state for all new resources.**

---

## **6. User Setup**

To enable users to interact with the **Resource Sharing and Access Control** feature, they must be assigned the appropriate cluster permissions along with resource-specific access.

### **Required Cluster Permissions**
Users must be assigned the following **cluster permissions** in `roles.yml`:

- **`cluster:admin/security/resource_access/*`** → Required to evaluate resource permissions.
- **Plugin-specific cluster permissions** → Required to interact with the plugin’s APIs.

#### **Example Role Configurations**
```yaml
sample_full_access:
  cluster_permissions:
    - 'cluster:admin/security/resource_access/*'
    - 'cluster:admin/sample-resource-plugin/*'

sample_read_access:
  cluster_permissions:
    - 'cluster:admin/security/resource_access/*'
    - 'cluster:admin/sample-resource-plugin/get'
```


### **User Access Rules**
1. **Users must have the required cluster permissions**
    - Even if a resource is shared with a user, they **cannot access it** unless they have the **plugin’s cluster permissions**.

2. **Granting plugin API permissions does not automatically grant resource access**
    - A resource must be **explicitly shared** with the user.
    - **Or, the user must be the resource owner.**

3. **No index permissions are required**
    - Access control is **handled at the cluster level**.
    - The `.opensearch_resource_sharing` index and the resource indices are protected under system index security.


### **Summary**
| **Requirement** | **Description**                                                                       |
|---------------|---------------------------------------------------------------------------------------|
| **Cluster Permission** | `cluster:admin/security/resource_access/*` required for resource evaluation.            |
| **Plugin API Permissions** | Users must also have relevant plugin API cluster permissions.                         |
| **Resource Sharing** | Access is granted only if the resource is shared with the user or they are the owner. |
| **No Index Permissions Needed** | The `.opensearch_resource_sharing` index and resource indices are system-protected.   |


---

## **7. Restrictions**
1. At present, **only resource owners can share/revoke access** to their own resources.
    - **Super admins** can manage access for any resource.
2. **Resources must be stored in a system index**, and system index protection **must be enabled**.
    - **Disabling system index protection** allows users to access resources **directly** if they have relevant index permissions.

---

## **8. REST APIs Introduced by the Security Plugin**

In addition to client methods, the **Security Plugin** introduces new **REST APIs** for managing resource access when the feature is enabled. These APIs allow users to **verify, grant, revoke, and list access** to resources.

---

### **1. Verify Access**
- **Endpoint:**
  ```
  POST /_plugins/_security/resources/verify_access
  ```
- **Description:**
  Verifies whether the current user has access to a specified resource.

#### **Request Body:**
```json
{
  "resource_id": "my-resource",
  "resource_index": "resource-index"
}
```

#### **Request Fields:**
| Field            | Type     | Description |
|-----------------|----------|-------------|
| `resource_id`   | String   | Unique identifier of the resource being accessed. |
| `resource_index`| String   | The OpenSearch index where the resource is stored. |

#### **Response:**
Returns whether the user has permission to access the resource.
```json
{
  "has_permission": true
}
```

#### **Response Fields:**
| Field            | Type    | Description |
|-----------------|---------|-------------|
| `has_permission` | Boolean | `true` if the user has access, `false` otherwise. |

---

### **2. Grant Access**
- **Endpoint:**
  ```
  POST /_plugins/_security/resources/share
  ```
- **Description:**
  Grants access to a resource for specified **users, roles, and backend roles**.

#### **Request Body:**
```json
{
  "resource_id": "my-resource",
  "resource_index": "resource-index",
  "share_with": {
      "users": ["shared-user-name"],
      "roles": ["shared-roles"],
      "backend_roles": ["shared-backend-roles"]
  }
}
```

#### **Request Fields:**
| Field            | Type    | Description |
|-----------------|---------|-------------|
| `resource_id`   | String  | The unique identifier of the resource to be shared. |
| `resource_index`| String  | The OpenSearch index where the resource is stored. |
| `share_with`    | Object  | Defines which **users, roles, or backend roles** will gain access. |
| `users`        | Array   | List of usernames allowed to access the resource. |
| `roles`        | Array   | List of role names granted access. |
| `backend_roles`| Array   | List of backend roles assigned to the resource. |

#### **Response:**
Returns the updated **resource sharing state**.
```json
{
  "sharing_info": {
    "source_idx": "resource-index",
    "resource_id": "my-resource",
    "created_by": {
      "user": "you"
    },
    "share_with": {
      "default": {
        "users": ["shared-user-name"],
        "roles": ["shared-roles"],
        "backend_roles": ["shared-backend-roles"]
      }
    }
  }
}
```

Note: `default` is a place-holder action-group that will eventually be replaced with actual action-groups in the future.

#### **Response Fields:**
| Field          | Type    | Description |
|---------------|---------|-------------|
| `sharing_info` | Object  | Contains information about how the resource is shared. |
| `source_idx`   | String  | The OpenSearch index containing the resource. |
| `resource_id`  | String  | The unique identifier of the resource being shared. |
| `created_by`   | Object  | Information about the user who created the sharing entry. |
| `share_with`   | Object  | Defines users, roles, and backend roles with access to the resource. |

---

### **3. Revoke Access**
- **Endpoint:**
  ```
  POST /_plugins/_security/resources/revoke
  ```
- **Description:**
  Revokes access to a resource for specific users, roles, or backend roles.

#### **Request Body:**
```json
{
  "resource_id": "my-resource",
  "resource_index": "resource-index",
  "entities_to_revoke": {
    "roles": ["shared-roles"]
  }
}
```

#### **Request Fields:**
| Field            | Type    | Description |
|-----------------|---------|-------------|
| `resource_id`   | String  | The unique identifier of the resource whose access is being revoked. |
| `resource_index`| String  | The OpenSearch index where the resource is stored. |
| `entities_to_revoke` | Object | Specifies which **users, roles, or backend roles** should have their access removed. |
| `roles`        | Array   | List of roles to revoke access from. |

#### **Response:**
Returns the updated **resource sharing state** after revocation.
```json
{
  "sharing_info": {
    "source_idx": "resource-index",
    "resource_id": "my-resource",
    "created_by": {
      "user": "admin"
    },
    "share_with": {
      "default": {
        "users": ["shared-user-name"],
        "backend_roles": ["shared-backend-roles"]
      }
    }
  }
}
```

Note: `default` is a place-holder action-group that will eventually be replaced with actual action-groups in the future.

#### **Response Fields:**
| Field          | Type    | Description |
|---------------|---------|-------------|
| `sharing_info` | Object  | Contains information about the updated resource sharing state. |
| `source_idx`   | String  | The OpenSearch index containing the resource. |
| `resource_id`  | String  | The unique identifier of the resource. |
| `created_by`   | Object  | Information about the user who created the sharing entry. |
| `share_with`   | Object  | Defines users, roles, and backend roles that still have access to the resource. |

---

### **4. List Accessible Resources**
- **Endpoint:**
  ```
  GET /_plugins/_security/resources/list/{resource_index}
  ```
- **Description:**
  Retrieves a list of **resources that the current user has access to** within the specified `{resource_index}`.

#### **Response:**
Returns an array of accessible resources.
```json
{
  "resources": [
    {
      "name": "my-resource-name",
      "description": "My resource description.",
      "attributes": {
        "type": "model"
      }
    }
  ]
}
```
*This is an example resource. Actual structure will vary based on your configuration.*

---

## **Additional Notes**
- **Feature Flag:** These APIs are available only when `plugins.security.resource_sharing.enabled` is set to `true` in the configuration.
- **Index Restrictions:** Resources must be stored in **system indices**, and **system index protection** must be enabled to prevent unauthorized access.

---

## **9. Best Practices**
### **For Plugin Developers**
- **Declare resources properly** in the `ResourceSharingExtension`.
- **Use the security client** instead of direct index queries to check access.
- **Implement a resource parser** to ensure correct resource extraction.

### **For Users & Admins**
- **Keep system index protection enabled** for better security.
- **Grant access only when necessary** to limit exposure.

---

## **Conclusion**
The **Resource Sharing and Access Control** feature enhances OpenSearch security by introducing an **additional layer of fine-grained access management** for plugin-defined shareableResources. While **Fine-Grained Access Control (FGAC)** is already enabled, this feature provides **even more granular control** specifically for **resource-level access** within plugins.

By implementing the **Service Provider Interface (SPI)**, utilizing the **security client**, and following **best practices**, developers can seamlessly integrate this feature into their plugins to enforce controlled resource sharing and access management.

For detailed implementation and examples, refer to the **[sample plugin](./sample-resource-plugin/README.md)** included in the security plugin repository.

---

## **License**
This project is licensed under the **Apache 2.0 License**.

---

## **Copyright**
© OpenSearch Contributors.
