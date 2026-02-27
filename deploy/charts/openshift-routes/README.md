# cert-manager Openshift Routes

<!-- see https://artifacthub.io/packages/helm/cert-manager/cert-manager-openshift-routes for the rendered version -->

## Helm Values

<!-- AUTO-GENERATED -->

#### **replicas** ~ `number`
> Default value:
> ```yaml
> 1
> ```
#### **logLevel** ~ `number`
> Default value:
> ```yaml
> 5
> ```
#### **namespace** ~ `string`
> Default value:
> ```yaml
> ""
> ```

This namespace allows you to define where the services are installed into. If not set then they use the namespace of the release. This is helpful when installing cert manager as a chart dependency (sub chart).
#### **fullnameOverride** ~ `string`

Override the "cert-manager.fullname" value. This value is used as part of most of the names of the resources created by this Helm chart.

#### **nameOverride** ~ `string`

Override the "cert-manager.name" value, which is used to annotate some of the resources that are created by this Chart (using "app.kubernetes.io/name"). NOTE: There are some inconsitencies in the Helm chart when it comes to these annotations (some resources use eg. "cainjector.name" which resolves to the value "cainjector").

#### **imageRegistry** ~ `string`
> Default value:
> ```yaml
> ghcr.io
> ```

The container registry used for openshift-routes images by default. This can include path prefixes (e.g. "artifactory.example.com/docker").

#### **imageNamespace** ~ `string`
> Default value:
> ```yaml
> cert-manager
> ```

The repository namespace used for openshift-routes images by default.  
Examples:  
- cert-manager  
- jetstack

#### **image.registry** ~ `string`

Deprecated: per-component registry prefix.  
  
If set, this value is *prepended* to the image repository that the chart would otherwise render. This applies both when `image.repository` is set and when the repository is computed from  
`imageRegistry` + `imageNamespace` + `image.name`.  
  
This can produce "double registry" style references such as  
`legacy.example.io/ghcr.io/cert-manager/...`. Prefer using the global  
`imageRegistry`/`imageNamespace` values.

#### **image.repository** ~ `string`
> Default value:
> ```yaml
> ""
> ```

Full repository override (takes precedence over `imageRegistry`, `imageNamespace`, and `image.name`). Example: ghcr.io/cert-manager/cert-manager-openshift-routes

#### **image.name** ~ `string`
> Default value:
> ```yaml
> cert-manager-openshift-routes
> ```

The image name for openshift-routes.  
This is used (together with `imageRegistry` and `imageNamespace`) to construct the full image reference.

#### **image.tag** ~ `string`

Override the image tag to deploy by setting this variable. If no value is set, the chart's appVersion is used.

#### **image.digest** ~ `string`

Target image digest. Override any tag, if set.  
For example:

```yaml
digest: sha256:0e072dddd1f7f8fc8909a2ca6f65e76c5f0d2fcfb8be47935ae3457e8bbceb20
```

#### **image.pullPolicy** ~ `string`
> Default value:
> ```yaml
> IfNotPresent
> ```

Kubernetes imagePullPolicy on Deployment.
#### **imagePullSecrets** ~ `array`
> Default value:
> ```yaml
> []
> ```

Optional secrets used for pulling the openshift-routes container image.
#### **serviceAccount.create** ~ `bool`
> Default value:
> ```yaml
> true
> ```

Specifies whether a service account should be created
#### **serviceAccount.name** ~ `string`

The name of the service account to use.  
If not set and create is true, a name is generated using the fullname template.

#### **serviceAccount.annotations** ~ `object`

Optional additional annotations to add to the controller's Service Account.

#### **rbac.create** ~ `bool`
> Default value:
> ```yaml
> true
> ```

create (Cluster-) Roles and RoleBindings for the ServiceAccount
#### **podAnnotations** ~ `object`
> Default value:
> ```yaml
> {}
> ```

Annotations to add to the openshift-routes pod.
#### **podSecurityContext** ~ `object`
> Default value:
> ```yaml
> runAsNonRoot: true
> seccompProfile:
>   type: RuntimeDefault
> ```

Pod Security Context.  
For more information, see [Configure a Security Context for a Pod or Container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/).

#### **securityContext** ~ `object`
> Default value:
> ```yaml
> allowPrivilegeEscalation: false
> capabilities:
>   drop:
>     - ALL
> readOnlyRootFilesystem: true
> ```

Container Security Context to be set on the controller component container. For more information, see [Configure a Security Context for a Pod or Container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/).

#### **resources** ~ `object`
> Default value:
> ```yaml
> {}
> ```

Kubernetes pod resources  
ref: https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/  
  
For example:

```yaml
resources:
  limits:
    memory: 128Mi
  requests:
    cpu: 100m
    memory: 128Mi
```
#### **nodeSelector** ~ `object`
> Default value:
> ```yaml
> kubernetes.io/os: linux
> ```

The nodeSelector on Pods tells Kubernetes to schedule Pods on the nodes with matching labels. For more information, see [Assigning Pods to Nodes](https://kubernetes.io/docs/concepts/scheduling-eviction/assign-pod-node/).  
  
This default ensures that Pods are only scheduled to Linux nodes. It prevents Pods being scheduled to Windows nodes in a mixed OS cluster.

#### **tolerations** ~ `array`
> Default value:
> ```yaml
> []
> ```

A list of Kubernetes Tolerations, if required. For more information, see [Toleration v1 core](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.27/#toleration-v1-core).  
  
For example:

```yaml
tolerations:
- key: foo.bar.com/role
  operator: Equal
  value: master
  effect: NoSchedule
```
#### **affinity** ~ `object`
> Default value:
> ```yaml
> {}
> ```

A Kubernetes Affinity, if required. For more information, see [Affinity v1 core](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.27/#affinity-v1-core).  
  
For example:

```yaml
affinity:
  nodeAffinity:
   requiredDuringSchedulingIgnoredDuringExecution:
     nodeSelectorTerms:
     - matchExpressions:
       - key: foo.bar.com/role
         operator: In
         values:
         - master
```
#### **metrics.enabled** ~ `bool`
> Default value:
> ```yaml
> false
> ```

when enabled, a service is created that exposes the metrics endpoint
#### **metrics.serviceMonitor.enabled** ~ `bool`
> Default value:
> ```yaml
> false
> ```

Create a ServiceMonitor to add openshift-routes to Prometheus.
#### **metrics.serviceMonitor.interval** ~ `string`
> Default value:
> ```yaml
> 60s
> ```

The interval to scrape metrics.
#### **omitHelmLabels** ~ `bool`
> Default value:
> ```yaml
> false
> ```

Omit Helm-specific labels. This is useful when generating a static manifest with `helm template`.

<!-- /AUTO-GENERATED -->