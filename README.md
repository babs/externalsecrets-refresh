# ExternalSecrets Refresh Job

A Kubernetes Job that triggers ExternalSecrets to refresh by patching their annotations and monitors the refresh status.

To be used for example in Helm Charts or ArgoCD applications.

## Features

- **Identifies** ExternalSecrets based on namespace and label selectors
- **Starts watching** for status changes before triggering refreshes to capture all events
- **Patches** each ExternalSecret with a `force-sync` annotation containing a UTC timestamp
- **Monitors** status updates, checking for updated `refreshTime` and `Ready` condition
- **Exit code** reflects overall success (0 = all refreshed, 1 = failures)

## How It Works

The job executes the following workflow to ensure reliable ExternalSecret refreshes:

1. **Initialization**: Configures structured logging and loads Kubernetes configuration (in-cluster or local).
2. **Discovery**: Lists all ExternalSecrets in the specified namespace(s) matching the label selector.
3. **Baseline Recording**: Captures the current `refreshTime` from each ExternalSecret's status for comparison.
4. **Watch Setup**: Initiates a Kubernetes watch on ExternalSecrets to monitor real-time status changes.
5. **Trigger Refresh**: Patches each ExternalSecret with a `force-sync` annotation set to the current UTC timestamp.
6. **Progress Monitoring**: Processes watch events to detect successful refreshes:
   - Checks for updated `refreshTime` (newer than baseline)
   - Verifies the `Ready` status condition is `True`
7. **Completion**: Continues monitoring until all ExternalSecrets refresh or the 60-second timeout expires.
8. **Result Evaluation**: Exits with code 0 if all succeeded, otherwise exits with 1.

## Usage

### Build the Docker Image

```bash
docker build -t externalsecrets-refresh:latest .
```

### Deploy to Kubernetes

The job can be configured via environment variables:

- `NAMESPACE`: Target namespace (defaults to job's namespace). Leave unset for all namespaces.
- `LABEL_SELECTOR`: Label selector to filter ExternalSecrets (e.g., `app=myapp,env=prod`)

**Deploy the job:**

```bash
kubectl apply -f job.yaml
```

**Customize for specific namespace:**

```yaml
env:
- name: NAMESPACE
  value: "production"
- name: LABEL_SELECTOR
  value: "app=myapp"
```

### Check Job Status

```bash
# Check job status
kubectl get jobs externalsecrets-refresh
# View logs
kubectl logs -f job/externalsecrets-refresh
# Check exit code
kubectl get job externalsecrets-refresh -o jsonpath='{.status.conditions[?(@.type=="Failed")].reason}'
```

## RBAC Permissions

The job requires:

- `get`, `list`, `watch`, `patch` on `externalsecrets`
- `get`, `watch` on `externalsecrets/status`

Two RBAC configurations are provided:

- **Role/RoleBinding**: For single namespace access (default)
- **ClusterRole/ClusterRoleBinding**: For cluster-wide access (commented out in job.yaml)

## Integration with Helm

To trigger this job during Helm deployment, add it as a pre-install hook:

```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: externalsecrets-refresh  annotations:
    helm.sh/hook: pre-install
    helm.sh/hook-weight: "-5"
    helm.sh/hook-delete-policy: before-hook-creation
spec:
  # ... rest of job spec
```

## Exit Codes

- `0`: All ExternalSecrets refreshed successfully
- `1`: One or more ExternalSecrets failed to refresh

## Troubleshooting

**No ExternalSecrets found:**

- Check namespace and label selector configuration
- Verify RBAC permissions

**Timeout after 60 seconds:**

- Check ExternalSecret controller is running
- Verify external secret store connectivity
- Review ExternalSecret status conditions for errors

**Permission denied:**

- Ensure ServiceAccount has proper RBAC permissions
- For cluster-wide access, use ClusterRole/ClusterRoleBinding
