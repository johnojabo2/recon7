import asyncio
import logging
from typing import Dict, Any, List, Optional
import httpx
from vuln.app_vuln.base import BaseAppVulnPlugin
from vuln.app_vuln.cluster import probe_and_cluster_targets, TargetCluster
from vuln.app_vuln.plugins import DEFAULT_PLUGINS

logger = logging.getLogger(__name__)


async def run_application_vulnerability_scans_async(
    targets: List[str],
    ip_resolutions: Optional[List[Dict[str, Any]]] = None,
    plugins: Optional[List[BaseAppVulnPlugin]] = None,
    max_concurrency: int = 10,
    timeout: float = 6.0,
) -> List[Dict[str, Any]]:
    """
    Asynchronous Enterprise Application Vulnerability Audit Runner.
    1. Clusters 100+ subdomains into unique application signatures to eliminate redundant probing.
    2. Concurrently executes non-destructive plugins against cluster representative URLs.
    3. Maps findings and evidence proofs across all member subdomains.
    """
    if not targets:
        return []

    active_plugins = plugins or DEFAULT_PLUGINS
    logger.info(f"[app_vuln.runner] Starting application vulnerability audit on {len(targets)} targets ({len(active_plugins)} active plugins)")

    # 1. Cluster subdomains by response signature
    clusters: List[TargetCluster] = []
    try:
        clusters = await probe_and_cluster_targets(
            subdomain_names=targets,
            ip_resolutions=ip_resolutions,
            timeout=min(timeout, 4.0),
            max_concurrency=max_concurrency,
        )
    except Exception as e:
        logger.warning(f"[app_vuln.runner] Pre-flight clustering error ({e}). Falling back to direct URL audit.")

    # Fallback: if no clusters returned, treat each unique target as an individual cluster
    if not clusters:
        for t in targets:
            url = t if t.startswith(("http://", "https://")) else f"https://{t}"
            clusters.append(
                TargetCluster(
                    cluster_id="direct",
                    representative_url=url,
                    origin_ip=None,
                    status_code=200,
                    title="Direct Target",
                    server_header="",
                    member_subdomains=[t],
                    member_urls=[url],
                )
            )

    logger.info(f"[app_vuln.runner] Dispatched active audits across {len(clusters)} distinct application clusters")

    all_findings: List[Dict[str, Any]] = []
    semaphore = asyncio.Semaphore(max_concurrency)
    limits = httpx.Limits(max_keepalive_connections=20, max_connections=max_concurrency)

    async with httpx.AsyncClient(
        timeout=timeout,
        verify=False,
        follow_redirects=True,
        headers={"User-Agent": "Mozilla/5.0 Recon7-AppVulnEngine/1.0"},
        limits=limits,
    ) as client:

        async def _audit_cluster(cluster: TargetCluster):
            async with semaphore:
                context = {
                    "cluster_id": cluster.cluster_id,
                    "cluster_domains": cluster.member_subdomains,
                    "origin_ip": cluster.origin_ip,
                    "server_header": cluster.server_header,
                }
                rep_url = cluster.representative_url

                for plugin in active_plugins:
                    try:
                        p_findings = await plugin.audit(
                            target_url=rep_url,
                            context=context,
                            client=client,
                        )
                        if p_findings:
                            logger.info(
                                f"[app_vuln.runner] Plugin '{plugin.plugin_id}' detected {len(p_findings)} finding(s) "
                                f"on {rep_url} (Affecting {len(cluster.member_subdomains)} subdomains)"
                            )
                            for f in p_findings:
                                f["cluster_id"] = cluster.cluster_id
                                f["cluster_domains"] = cluster.member_subdomains
                                f["affected_subdomains_count"] = len(cluster.member_subdomains)
                                all_findings.append(f)
                    except Exception as e:
                        logger.debug(f"[app_vuln.runner] Error running plugin '{plugin.plugin_id}' on {rep_url}: {e}")

        tasks = [_audit_cluster(c) for c in clusters]
        await asyncio.gather(*tasks, return_exceptions=True)

    logger.info(f"[app_vuln.runner] Application audit completed with {len(all_findings)} confirmed findings")
    return all_findings


def run_app_vuln_scans_sync(
    targets: List[str],
    ip_resolutions: Optional[List[Dict[str, Any]]] = None,
    plugins: Optional[List[BaseAppVulnPlugin]] = None,
    max_concurrency: int = 10,
    timeout: float = 6.0,
) -> List[Dict[str, Any]]:
    """
    Synchronous bridge for pipeline workers running inside thread pools.
    """
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            # If called inside an existing running event loop in the same thread
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                return pool.submit(
                    asyncio.run,
                    run_application_vulnerability_scans_async(
                        targets=targets,
                        ip_resolutions=ip_resolutions,
                        plugins=plugins,
                        max_concurrency=max_concurrency,
                        timeout=timeout,
                    ),
                ).result()
        else:
            return loop.run_until_complete(
                run_application_vulnerability_scans_async(
                    targets=targets,
                    ip_resolutions=ip_resolutions,
                    plugins=plugins,
                    max_concurrency=max_concurrency,
                    timeout=timeout,
                )
            )
    except RuntimeError:
        return asyncio.run(
            run_application_vulnerability_scans_async(
                targets=targets,
                ip_resolutions=ip_resolutions,
                plugins=plugins,
                max_concurrency=max_concurrency,
                timeout=timeout,
            )
        )
