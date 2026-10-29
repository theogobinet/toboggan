import json
import shlex
from urllib.parse import quote

# External library imports
from loguru import logger

# Local application/library specific imports
from toboggan.core.action import BaseAction
from toboggan.core.utils.jwt import parse_jwt


class KubeCheckAction(BaseAction):
    DESCRIPTION = (
        "Check for Kubernetes environment and enumerate basic pod-level access."
    )

    def run(self):
        logger.info("Kubernetes Environment Check")

        service_account_dir = "/var/run/secrets/kubernetes.io/serviceaccount"
        token_path = f"{service_account_dir}/token"
        cert_path = f"{service_account_dir}/ca.crt"
        namespace_path = f"{service_account_dir}/namespace"

        token = self._executor.remote_execute(f"cat {token_path}").strip()
        if not token or token.startswith("cat:"):
            logger.warning("No Kubernetes service account token found.")
            return

        try:
            _, claims, _ = parse_jwt(token)
        except Exception as exc:
            logger.warning(f"Could not decode service account token claims: {exc}")
            claims = {}

        logger.info(f"Token subject: {claims.get('sub', 'unknown')}")
        kubernetes_claims = claims.get("kubernetes.io", {})
        if not isinstance(kubernetes_claims, dict):
            kubernetes_claims = {}
        pod_claim = kubernetes_claims.get("pod", {})
        if not isinstance(pod_claim, dict):
            pod_claim = {}
        pod_name = pod_claim.get("name")
        pod_uid = pod_claim.get("uid")
        node_claim = kubernetes_claims.get("node", {})
        node_name_hint = (
            node_claim.get("name") if isinstance(node_claim, dict) else None
        )

        namespace = (
            kubernetes_claims.get("namespace")
            or claims.get("kubernetes.io/serviceaccount/namespace")
        )
        if not namespace:
            namespace = self._executor.remote_execute(f"cat {namespace_path}").strip()
        namespace = namespace or "default"
        logger.info(f"Using namespace: {namespace}")

        api_server = self._executor.remote_execute(
            'if [ -n "$KUBERNETES_SERVICE_HOST" ] && '
            '[ -n "$KUBERNETES_SERVICE_PORT" ]; then '
            'printf "https://%s:%s" "$KUBERNETES_SERVICE_HOST" '
            '"$KUBERNETES_SERVICE_PORT"; fi'
        ).strip()
        if not api_server:
            logger.warning("Kubernetes API server environment variables not found.")
            return
        logger.info(f"Kubernetes API server: {api_server}")

        curl_path = self._executor.os_helper.get_command_location("curl")
        if not curl_path:
            logger.warning("No usable curl binary found.")
            return

        curl_base = (
            f"{curl_path} -sS --max-time 10 --cacert {shlex.quote(cert_path)} "
            f'-H "Authorization: Bearer $(cat {shlex.quote(token_path)})"'
        )
        ssrr_payload = json.dumps(
            {
                "apiVersion": "authorization.k8s.io/v1",
                "kind": "SelfSubjectRulesReview",
                "spec": {"namespace": namespace},
            }
        )
        ssrr_cmd = (
            f"{curl_base} -H 'Content-Type: application/json' "
            f"-X POST -d {shlex.quote(ssrr_payload)} "
            f"{shlex.quote(api_server + '/apis/authorization.k8s.io/v1/selfsubjectrulesreviews')}"
        )
        ssrr_raw = self._executor.remote_execute(ssrr_cmd, timeout=10)
        try:
            ssrr_json = json.loads(ssrr_raw)
        except (TypeError, ValueError):
            logger.warning("Could not parse SelfSubjectRulesReview response.")
        else:
            if (
                isinstance(ssrr_json, dict)
                and ssrr_json.get("kind") == "SelfSubjectRulesReview"
            ):
                self._analyze_rules(ssrr_json)
            else:
                reason = (
                    ssrr_json.get("reason", "unexpected response")
                    if isinstance(ssrr_json, dict)
                    else "unexpected response"
                )
                logger.warning(f"SelfSubjectRulesReview failed: {reason}")

        pods_url = f"{api_server}/api/v1/namespaces/{quote(namespace, safe='')}/pods"
        pods_raw = self._executor.remote_execute(
            f"{curl_base} {shlex.quote(pods_url)}", timeout=10
        )
        try:
            pods_json = json.loads(pods_raw)
        except (TypeError, ValueError):
            logger.warning("Could not parse the namespace Pod response.")
            pods_json = {}

        current_pod = None
        if isinstance(pods_json, dict) and pods_json.get("kind") == "PodList":
            pods = pods_json.get("items", [])
            logger.success(f"Listed {len(pods)} pods in namespace {namespace}.")
            for pod in pods:
                metadata = pod.get("metadata", {})
                logger.info(
                    f"Pod {metadata.get('name', 'unknown')}: "
                    f"{pod.get('status', {}).get('phase', 'unknown')} on "
                    f"{pod.get('spec', {}).get('nodeName', 'unknown node')}"
                )
                if (pod_name and metadata.get("name") == pod_name) or (
                    pod_uid and metadata.get("uid") == pod_uid
                ):
                    if not pod_uid or metadata.get("uid") == pod_uid:
                        current_pod = pod
        elif isinstance(pods_json, dict) and pods_json.get("kind") == "Status":
            logger.info(
                "Listing namespace pods: "
                f"{pods_json.get('reason', pods_json.get('status', 'unknown'))}"
            )

        # A service account can have get permission for its Pod without list permission.
        if current_pod is None and pod_name:
            pod_url = f"{pods_url}/{quote(pod_name, safe='')}"
            pod_raw = self._executor.remote_execute(
                f"{curl_base} {shlex.quote(pod_url)}", timeout=10
            )
            try:
                pod_json = json.loads(pod_raw)
            except (TypeError, ValueError):
                logger.warning("Could not parse the current Pod response.")
            else:
                if isinstance(pod_json, dict) and pod_json.get("kind") == "Pod":
                    metadata = pod_json.get("metadata", {})
                    if not pod_uid or metadata.get("uid") == pod_uid:
                        current_pod = pod_json
                    else:
                        logger.warning("Pod UID does not match the token claim.")
                elif isinstance(pod_json, dict):
                    logger.info(
                        f"Reading current Pod: {pod_json.get('reason', 'unavailable')}"
                    )

        if current_pod:
            spec = current_pod.get("spec", {})
            status = current_pod.get("status", {})
            logger.info(f"Current pod: {current_pod.get('metadata', {}).get('name')}")
            logger.info(f"Node name: {spec.get('nodeName', 'unavailable')}")
            logger.info(f"Node IP: {status.get('hostIP', 'unavailable')}")
            logger.info(f"Pod IP: {status.get('podIP', 'unavailable')}")
        elif pod_name:
            logger.info(f"Current pod from token claim: {pod_name}")
            if node_name_hint:
                logger.info(f"Node name from token claim (unverified): {node_name_hint}")
            logger.info("Node address unavailable without access to the Pod object.")
        else:
            logger.info("Current pod is not identified by this token.")

    def _analyze_rules(self, ssrr_json: dict) -> None:
        """Summarize useful permissions without fetching sensitive objects."""
        status = ssrr_json.get("status", {})
        if status.get("incomplete"):
            logger.warning("Permission summary is incomplete.")

        interesting = {
            "pods",
            "pods/exec",
            "pods/portforward",
            "secrets",
            "configmaps",
            "services",
            "endpointslices",
            "serviceaccounts",
            "roles",
            "rolebindings",
            "clusterroles",
            "clusterrolebindings",
            "deployments",
            "daemonsets",
            "nodes",
        }
        found = False
        for rule in status.get("resourceRules", []):
            verbs = rule.get("verbs", [])
            groups = rule.get("apiGroups", [])
            for resource in rule.get("resources", []):
                if resource in interesting or resource == "*":
                    found = True
                    logger.info(
                        f"Permission {','.join(groups) or 'core'}/{resource}: "
                        f"{', '.join(verbs)}"
                    )
        if not found:
            logger.info("No high-value resource permissions reported.")
