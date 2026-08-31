from vuln.app_vuln.plugins.cors_audit import CorsAuditPlugin
from vuln.app_vuln.plugins.graphql_audit import GraphQLAuditPlugin
from vuln.app_vuln.plugins.ssti_probe import SstiProbePlugin
from vuln.app_vuln.plugins.js_harvester import JsHarvesterPlugin
from vuln.app_vuln.plugins.redirect_probe import RedirectProbePlugin

DEFAULT_PLUGINS = [
    CorsAuditPlugin(),
    GraphQLAuditPlugin(),
    SstiProbePlugin(),
    JsHarvesterPlugin(),
    RedirectProbePlugin(),
]

__all__ = [
    "CorsAuditPlugin",
    "GraphQLAuditPlugin",
    "SstiProbePlugin",
    "JsHarvesterPlugin",
    "RedirectProbePlugin",
    "DEFAULT_PLUGINS",
]
