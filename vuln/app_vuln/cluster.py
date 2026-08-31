import re
import hashlib
import logging
import asyncio
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional, Set
import httpx
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)


@dataclass
class TargetCluster:
    """
    Represents a group of subdomains/endpoints hosting the exact same underlying application.
    """
    cluster_id: str
    representative_url: str
    origin_ip: Optional[str]
    status_code: int
    title: str
    server_header: str
    member_subdomains: List[str] = field(default_factory=list)
    member_urls: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cluster_id": self.cluster_id,
            "representative_url": self.representative_url,
            "origin_ip": self.origin_ip,
            "status_code": self.status_code,
            "title": self.title,
            "server_header": self.server_header,
            "member_subdomains": self.member_subdomains,
            "member_urls": self.member_urls,
            "total_members": len(self.member_subdomains),
        }


def compute_cluster_signature(
    origin_ip: Optional[str],
    status_code: int,
    title: str,
    server: str,
    body_snippet: str = "",
) -> str:
    """
    Generates a deterministic 16-character SHA-256 signature hash for an application profile:
    Hash(Origin IP + Status + Normalized Title + Normalized Server + Body Structure)
    """
    ip_norm = (origin_ip or "any_ip").strip().lower()
    title_norm = re.sub(r"\s+", " ", (title or "no_title").strip().lower())
    server_norm = (server or "no_server").strip().lower()
    
    # Extract structural length tag (rounded to nearest 200 bytes to smooth dynamic timestamps)
    body_len_bucket = len(body_snippet) // 200 * 200 if body_snippet else 0

    raw_key = f"{ip_norm}|{status_code}|{title_norm}|{server_norm}|{body_len_bucket}"
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()[:16]


async def probe_and_cluster_targets(
    subdomain_names: List[str],
    ip_resolutions: Optional[List[Dict[str, Any]]] = None,
    timeout: float = 4.0,
    max_concurrency: int = 15,
) -> List[TargetCluster]:
    """
    Performs fast, lightweight pre-flight HEAD/GET requests against all subdomains
    and clusters identical web applications into TargetCluster buckets.
    """
    if not subdomain_names:
        return []

    # Map subdomains to origin IP if known
    sub_to_ip: Dict[str, str] = {}
    if ip_resolutions:
        for item in ip_resolutions:
            sub = item.get("subdomain")
            ips = item.get("ips", [])
            if sub and ips:
                sub_to_ip[sub.lower()] = ips[0]

    unique_subdomains = list(dict.fromkeys(s.strip().lower() for s in subdomain_names if s and s.strip()))
    logger.info(f"[app_vuln.cluster] Pre-flight clustering {len(unique_subdomains)} subdomains (Concurrency: {max_concurrency})")

    semaphore = asyncio.Semaphore(max_concurrency)
    clusters_by_sig: Dict[str, TargetCluster] = {}
    unreachable_targets: List[str] = []

    async def _inspect_subdomain(sub: str, client: httpx.AsyncClient):
        async with semaphore:
            candidate_urls = [f"https://{sub}", f"http://{sub}"]
            origin_ip = sub_to_ip.get(sub)

            for url in candidate_urls:
                try:
                    resp = await client.get(url)
                    headers = {k.lower(): str(v) for k, v in resp.headers.items()}
                    server_hdr = headers.get("server", "")
                    
                    # Extract page title
                    title = ""
                    try:
                        soup = BeautifulSoup(resp.text[:20000], "html.parser")
                        if soup.title and soup.title.string:
                            title = soup.title.string.strip()
                    except Exception:
                        pass

                    sig = compute_cluster_signature(
                        origin_ip=origin_ip,
                        status_code=resp.status_code,
                        title=title,
                        server=server_hdr,
                        body_snippet=resp.text[:1000],
                    )

                    if sig not in clusters_by_sig:
                        clusters_by_sig[sig] = TargetCluster(
                            cluster_id=sig,
                            representative_url=str(resp.url),
                            origin_ip=origin_ip,
                            status_code=resp.status_code,
                            title=title,
                            server_header=server_hdr,
                            member_subdomains=[sub],
                            member_urls=[str(resp.url)],
                        )
                    else:
                        cluster = clusters_by_sig[sig]
                        if sub not in cluster.member_subdomains:
                            cluster.member_subdomains.append(sub)
                        if str(resp.url) not in cluster.member_urls:
                            cluster.member_urls.append(str(resp.url))
                    return
                except (httpx.RequestError, httpx.TimeoutException):
                    continue
                except Exception as e:
                    logger.debug(f"[app_vuln.cluster] Error inspecting {url}: {e}")
                    continue

            unreachable_targets.append(sub)

    limits = httpx.Limits(max_keepalive_connections=20, max_connections=max_concurrency)
    async with httpx.AsyncClient(
        timeout=timeout,
        verify=False,
        follow_redirects=True,
        headers={"User-Agent": "Mozilla/5.0 Recon7-ClusterEngine/1.0"},
        limits=limits,
    ) as client:
        tasks = [_inspect_subdomain(s, client) for s in unique_subdomains]
        await asyncio.gather(*tasks, return_exceptions=True)

    cluster_list = list(clusters_by_sig.values())
    total_clustered = sum(len(c.member_subdomains) for c in cluster_list)
    logger.info(
        f"[app_vuln.cluster] Clustered {total_clustered} live subdomains into "
        f"{len(cluster_list)} unique application profiles ({len(unreachable_targets)} unreachable)"
    )

    return cluster_list
