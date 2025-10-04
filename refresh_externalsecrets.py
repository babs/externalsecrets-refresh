#!/usr/bin/env python3
"""
ExternalSecret Refresh Job
Triggers refresh of ExternalSecrets by updating annotations and monitors their status.
"""
import logging
import os
import sys
import time
from datetime import datetime
from datetime import timezone
from typing import Any
from typing import cast
from typing import Dict
from typing import Iterator
from typing import List
from typing import Optional

import dotenv
import structlog
from kubernetes import client
from kubernetes import config
from kubernetes import watch
from kubernetes.client.rest import ApiException

# Load .env if present
dotenv.load_dotenv()


def configure_structlog() -> None:
    """Configure structured logging."""
    shared_processors = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
    ]

    if sys.stdout.isatty():
        # Console output for terminals
        processors = shared_processors + [structlog.dev.ConsoleRenderer()]
    else:
        # JSON output for non-terminal (Kubernetes logs)
        processors = shared_processors + [
            structlog.processors.dict_tracebacks,
            structlog.processors.JSONRenderer(),
        ]

    structlog.configure(
        processors=processors,
        wrapper_class=structlog.stdlib.BoundLogger,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )

    # Set root logger level
    logging.basicConfig(
        format="%(message)s",
        level=logging.INFO,
    )


configure_structlog()
logger = structlog.get_logger()


REFRESH_TIMEOUT = 60  # seconds
FORCE_REFRESH_ANNOTATION = "force-sync"


class ExternalSecretRefresher:
    """Manages the refresh process for ExternalSecrets."""

    REFRESH_TIMEOUT = 60  # seconds
    FORCE_REFRESH_ANNOTATION = "force-sync"

    def __init__(self, namespace: Optional[str] = None, label_selector: Optional[str] = None):
        """
        Initialize the refresher.

        Args:
            namespace: Kubernetes namespace to watch. If None, uses all namespaces.
            label_selector: Label selector to filter ExternalSecrets.
        """
        try:
            config.load_incluster_config()
            logger.info("kubernetes_config_loaded", config_type="in-cluster")
        except config.ConfigException:
            config.load_kube_config()
            logger.info("kubernetes_config_loaded", config_type="local")

        self.custom_api = client.CustomObjectsApi()
        self.namespace = namespace
        self.label_selector = label_selector or ""
        self.group = "external-secrets.io"
        self.version = "v1beta1"
        self.plural = "externalsecrets"

        # Bind logger with context
        self.logger = logger.bind(
            namespace=self.namespace or "all", label_selector=self.label_selector or "none"
        )

    def list_external_secrets(self) -> List[Dict[str, Any]]:
        """
        List all ExternalSecrets matching the criteria.

        Returns:
            List of ExternalSecret objects.
        """
        try:
            if self.namespace:
                response = self.custom_api.list_namespaced_custom_object(
                    group=self.group,
                    version=self.version,
                    namespace=self.namespace,
                    plural=self.plural,
                    label_selector=self.label_selector,
                )
            else:
                response = self.custom_api.list_cluster_custom_object(
                    group=self.group,
                    version=self.version,
                    plural=self.plural,
                    label_selector=self.label_selector,
                )

            items = cast(List[Dict[str, Any]], response.get("items", []))
            self.logger.info("externalsecrets_listed", count=len(items))
            return items
        except ApiException as e:
            self.logger.error("externalsecrets_list_failed", error=str(e))
            raise

    def get_last_refresh_time(self, external_secret: Dict[str, Any]) -> Optional[datetime]:
        """
        Extract the last refresh time from ExternalSecret status.

        Args:
            external_secret: ExternalSecret object.

        Returns:
            Last refresh time as datetime or None.
        """
        status = external_secret.get("status", {})
        refresh_time_str = status.get("refreshTime")

        if not refresh_time_str:
            return None

        try:
            # Parse ISO 8601 timestamp
            return datetime.fromisoformat(refresh_time_str.replace("Z", "+00:00"))
        except (ValueError, AttributeError) as e:
            self.logger.warning("refresh_time_parse_failed", refresh_time=refresh_time_str, error=str(e))
            return None

    def patch_external_secret(self, name: str, namespace: str, timestamp: str) -> bool:
        """
        Patch ExternalSecret to trigger refresh by updating annotation.

        Args:
            name: Name of the ExternalSecret.
            namespace: Namespace of the ExternalSecret.
            timestamp: Timestamp to use for the force-sync annotation.

        Returns:
            True if patch succeeded, False otherwise.
        """
        patch = {"metadata": {"annotations": {FORCE_REFRESH_ANNOTATION: timestamp}}}

        try:
            self.custom_api.patch_namespaced_custom_object(
                group=self.group,
                version=self.version,
                namespace=namespace,
                plural=self.plural,
                name=name,
                body=patch,
            )
            self.logger.info(
                "externalsecret_patched",
                external_secret=f"{namespace}/{name}",
                annotation=FORCE_REFRESH_ANNOTATION,
                timestamp=timestamp,
            )
            return True
        except ApiException as e:
            self.logger.error(
                "externalsecret_patch_failed", external_secret=f"{namespace}/{name}", error=str(e)
            )
            return False

    def start_watch(self, timeout: int = REFRESH_TIMEOUT) -> tuple[watch.Watch, Iterator[Any]]:
        """
        Start watching ExternalSecrets for status updates.

        Args:
            timeout: Maximum time to wait in seconds.

        Returns:
            Tuple of (watch.Watch instance, iterator for events).
        """
        w = watch.Watch()

        # Determine watch parameters based on namespace
        if self.namespace:
            watch_func = self.custom_api.list_namespaced_custom_object
            watch_kwargs = {
                "group": self.group,
                "version": self.version,
                "namespace": self.namespace,
                "plural": self.plural,
                "label_selector": self.label_selector,
                "timeout_seconds": timeout,
            }
        else:
            watch_func = self.custom_api.list_cluster_custom_object
            watch_kwargs = {
                "group": self.group,
                "version": self.version,
                "plural": self.plural,
                "label_selector": self.label_selector,
                "timeout_seconds": timeout,
            }

        event_stream = w.stream(watch_func, **watch_kwargs)
        return w, event_stream

    def watch_for_refresh(
        self,
        event_stream,
        watcher,
        secrets_to_watch: Dict[str, Optional[datetime]],
        start_time: float,
        timeout: int = REFRESH_TIMEOUT,
    ) -> Dict[str, bool]:
        """
        Watch ExternalSecrets for status updates indicating successful refresh.

        Args:
            event_stream: Iterator of watch events.
            watcher: watch.Watch instance to stop when done.
            secrets_to_watch: Dict mapping "namespace/name" to initial refresh times.
            start_time: Time when watching started.
            timeout: Maximum time to wait in seconds.

        Returns:
            Dict mapping "namespace/name" to refresh success status.
        """
        results = {key: False for key in secrets_to_watch.keys()}

        try:
            for event in event_stream:
                # Check timeout
                if time.time() - start_time > timeout:
                    self.logger.warning("watch_timeout_reached", timeout_seconds=timeout)
                    break

                obj = event["object"]
                event_type = event["type"]

                name = obj["metadata"]["name"]
                namespace = obj["metadata"]["namespace"]
                key = f"{namespace}/{name}"

                # Only process events for secrets we're watching
                if key not in secrets_to_watch:
                    continue

                # Skip if already marked as refreshed
                if results[key]:
                    continue

                # Extract status information
                new_refresh_time = self.get_last_refresh_time(obj)
                old_refresh_time = secrets_to_watch[key]

                status = obj.get("status", {})
                conditions = status.get("conditions", [])

                # Find Ready condition
                is_ready = False
                ready_reason = None
                ready_message = None

                for condition in conditions:
                    if condition.get("type") == "Ready":
                        is_ready = condition.get("status") == "True"
                        ready_reason = condition.get("reason")
                        ready_message = condition.get("message")
                        break

                # Build structured log context
                log_context = {
                    "external_secret": key,
                    "event_type": event_type,
                    "is_ready": is_ready,
                    "has_new_refresh_time": new_refresh_time is not None,
                    "has_old_refresh_time": old_refresh_time is not None,
                }

                if new_refresh_time:
                    log_context["new_refresh_time"] = new_refresh_time.isoformat()
                if old_refresh_time:
                    log_context["old_refresh_time"] = old_refresh_time.isoformat()
                if ready_reason:
                    log_context["ready_reason"] = ready_reason
                if ready_message:
                    log_context["ready_message"] = ready_message

                event_logger = self.logger.bind(**log_context)

                # Evaluate refresh status
                refresh_successful = False
                if new_refresh_time and old_refresh_time:
                    refresh_successful = new_refresh_time > old_refresh_time and is_ready
                elif new_refresh_time and is_ready:
                    refresh_successful = True

                if not is_ready:
                    event_logger.warning("externalsecret_status_check")
                elif refresh_successful:
                    event_logger.info("externalsecret_refresh_verified")
                    results[key] = True

                # Check completion
                if all(results.values()):
                    self.logger.info("all_externalsecrets_refreshed", total_count=len(results))
                    break

        except ApiException as e:
            self.logger.error("watch_error", error=str(e))
        finally:
            watcher.stop()

        return results

    def refresh_and_verify(self) -> int:
        """
        Main workflow: identify, patch, watch, and verify ExternalSecrets.

        Returns:
            Exit code (0 for success, non-zero for failure).
        """
        # List ExternalSecrets
        self.logger.info("discovering_externalsecrets", operation="list")
        external_secrets = self.list_external_secrets()

        if not external_secrets:
            self.logger.warning("no_externalsecrets_found")
            return 0  # Nothing to do, not an error

        # Record current refresh times for comparison
        self.logger.info(
            "baseline_collection_started",
            operation="record_initial_state",
            externalsecret_count=len(external_secrets),
        )
        secrets_to_watch = {}

        for es in external_secrets:
            name = es["metadata"]["name"]
            namespace = es["metadata"]["namespace"]
            key = f"{namespace}/{name}"

            refresh_time = self.get_last_refresh_time(es)
            secrets_to_watch[key] = refresh_time

            self.logger.info(
                "externalsecret_initial_state",
                external_secret=key,
                last_refresh_time=refresh_time.isoformat() if refresh_time else None,
            )

        # Start watching BEFORE patching to avoid race conditions
        self.logger.info(
            "watch_started",
            operation="monitor_status_changes",
            timeout_seconds=REFRESH_TIMEOUT,
            reason="capture_all_refresh_events",
        )
        watcher, event_stream = self.start_watch(timeout=REFRESH_TIMEOUT)
        watch_start_time = time.time()

        # Patch all ExternalSecrets to trigger refresh
        sync_timestamp = datetime.now(timezone.utc).isoformat()
        self.logger.info(
            "refresh_triggered",
            operation="patch_annotations",
            sync_timestamp=sync_timestamp,
            externalsecret_count=len(external_secrets),
        )

        patch_results = {}

        for es in external_secrets:
            name = es["metadata"]["name"]
            namespace = es["metadata"]["namespace"]
            key = f"{namespace}/{name}"

            success = self.patch_external_secret(name, namespace, sync_timestamp)
            patch_results[key] = success

        # Evaluate patch results
        failed_patches = [k for k, v in patch_results.items() if not v]
        successful_patches = [k for k, v in patch_results.items() if v]

        if failed_patches:
            self.logger.error(
                "patch_failures_detected",
                failed_count=len(failed_patches),
                successful_count=len(successful_patches),
                total_count=len(patch_results),
            )
            for key in failed_patches:
                self.logger.error("patch_failed", external_secret=key)

        # Process watch events for status updates
        self.logger.info(
            "monitoring_refresh_progress",
            operation="process_watch_events",
            externalsecret_count=len(secrets_to_watch),
        )
        refresh_results = self.watch_for_refresh(
            event_stream, watcher, secrets_to_watch, watch_start_time, timeout=REFRESH_TIMEOUT
        )

        # Analyze and report results
        self.logger.info("results_analysis_started", operation="evaluate_refresh_outcomes")

        successful = [k for k, v in refresh_results.items() if v]
        failed = [k for k, v in refresh_results.items() if not v]

        # Log individual results with structured data
        for key in successful:
            self.logger.info("externalsecret_result", external_secret=key, status="refreshed")

        for key in failed:
            self.logger.error("externalsecret_result", external_secret=key, status="failed")

        # Compute exit code
        exit_code = 0 if len(failed) == 0 else 1

        # Final summary with all relevant metrics
        summary_context = {
            "total_count": len(refresh_results),
            "successful_count": len(successful),
            "failed_count": len(failed),
            "exit_code": exit_code,
            "success_rate": len(successful) / len(refresh_results) if refresh_results else 0,
        }

        if exit_code == 0:
            self.logger.info("workflow_complete", status="success", **summary_context)
        else:
            self.logger.error("workflow_complete", status="failure", **summary_context)

        return exit_code


def main():
    """Main entry point."""
    namespace = os.getenv("NAMESPACE")
    label_selector = os.getenv("LABEL_SELECTOR")

    logger.info(
        "job_started",
        job_name="ExternalSecret Refresh Job",
        namespace=namespace or "all",
        label_selector=label_selector or "none",
    )

    refresher = ExternalSecretRefresher(namespace=namespace, label_selector=label_selector)

    exit_code = refresher.refresh_and_verify()
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
