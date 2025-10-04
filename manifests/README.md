# ExternalSecret Refresh Job - Deployment Manifests

This directory contains Kubernetes manifests for deploying the ExternalSecret refresh job.
The manifests are split into individual files for better organization.

## Deployment

### Namespace-Scoped Access (Recommended)

Apply the manifests in order:

```bash
kubectl apply -f 01-job.yaml
kubectl apply -f 02-serviceaccount.yaml
kubectl apply -f 03-role.yaml
kubectl apply -f 04-rolebinding.yaml
```

Or deploy all at once:

```bash
kubectl apply -f .
```

### Cluster-Wide Access

For cluster-wide access (when `NAMESPACE` environment variable is not set):

```bash
kubectl apply -f clusterrole.yaml
kubectl apply -f clusterrolebinding.yaml
```

## Manifest Files

- `01-job.yaml` - Main Kubernetes Job definition
- `02-serviceaccount.yaml` - ServiceAccount for the job
- `03-role.yaml` - RBAC Role (namespace-scoped permissions)
- `04-rolebinding.yaml` - RBAC RoleBinding
- `clusterrole.yaml` - Alternative ClusterRole (cluster-wide permissions)
- `clusterrolebinding.yaml` - Alternative ClusterRoleBinding

## Configuration

The job can be configured using environment variables:

- `NAMESPACE` - Kubernetes namespace to watch (default: current namespace)
- `LABEL_SELECTOR` - Label selector to filter ExternalSecrets (default: none)

Example:

```bash
kubectl set env job/externalsecrets-refresh NAMESPACE=my-namespace
kubectl set env job/externalsecrets-refresh LABEL_SELECTOR="app=myapp"
```
