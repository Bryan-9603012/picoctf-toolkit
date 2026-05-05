# postprocess/source_aware.py
"""
Source-Aware Mode

Analyzes application structure to understand:
- Route patterns (API, admin, auth)
- Authentication mechanisms
- Debug/endpoints
- Data flow patterns
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Any
from collections import defaultdict
import re


@dataclass
class RoutePattern:
    """Discovered route pattern"""
    path: str
    method: str
    category: str
    has_auth: bool = False
    is_sensitive: bool = False
    parent_route: Optional[str] = None


@dataclass
class AuthMechanism:
    """Discovered authentication mechanism"""
    type: str  # bearer, basic, cookie, form, jwt
    endpoint: str
    strength: str  # weak, medium, strong
    has_mfa: bool = False


@dataclass
class ApplicationMap:
    """Complete application structure map"""
    base_url: str
    routes: List[RoutePattern] = field(default_factory=list)
    auth_mechanisms: List[AuthMechanism] = field(default_factory=list)
    debug_endpoints: List[str] = field(default_factory=list)
    sensitive_routes: List[str] = field(default_factory=list)
    api_endpoints: List[str] = field(default_factory=list)
    admin_routes: List[str] = field(default_factory=list)


ROUTE_CATEGORIES = {
    "api": ["/api", "/v1", "/v2", "/rest", "/graphql"],
    "auth": ["/auth", "/login", "/logout", "/register", "/signup", "/password", "/reset"],
    "admin": ["/admin", "/manage", "/console", "/dashboard", "/settings"],
    "debug": ["/debug", "/actuator", "/heapdump", "/env", "/info", "/health"],
    "user": ["/user", "/profile", "/account", "/me", "/settings"],
    "data": ["/data", "/export", "/download", "/backup", "/db"],
    "static": ["/static", "/assets", "/images", "/css", "/js"],
}


def categorize_route(path: str) -> str:
    """Categorize a route based on path patterns"""
    path_lower = path.lower()
    
    for category, patterns in ROUTE_CATEGORIES.items():
        for pattern in patterns:
            if pattern in path_lower:
                return category
    
    return "unknown"


def is_sensitive_route(path: str) -> bool:
    """Determine if route is sensitive"""
    sensitive_patterns = [
        r"/admin",
        r"/api/.*/admin",
        r"/config",
        r"/env",
        r"/\.env",
        r"/heapdump",
        r"/actuator",
        r"/debug",
        r"/内部",
        r"/private",
        r"/backup",
        r"/\.git",
        r"/\.svn",
        r"/credentials",
        r"/secrets",
    ]
    
    for pattern in sensitive_patterns:
        if re.search(pattern, path, re.IGNORECASE):
            return True
    
    return False


def is_api_endpoint(path: str) -> bool:
    """Determine if route is API endpoint"""
    api_patterns = [
        r"/api/",
        r"/v\d+",
        r"/rest/",
        r"/graphql",
        r"/graphql",
        r"\.(json|xml)$",
    ]
    
    for pattern in api_patterns:
        if re.search(pattern, path, re.IGNORECASE):
            return True
    
    return False


def is_admin_route(path: str) -> bool:
    """Determine if route is admin interface"""
    admin_patterns = [
        r"/admin",
        r"/manage",
        r"/console",
        r"/dashboard",
        r"/panel",
        r"/backend",
    ]
    
    for pattern in admin_patterns:
        if re.search(pattern, path, re.IGNORECASE):
            return True
    
    return False


def is_debug_endpoint(path: str) -> bool:
    """Determine if endpoint is debug/monitoring"""
    debug_patterns = [
        r"/debug",
        r"/actuator",
        r"/heapdump",
        r"/env",
        r"/info",
        r"/health",
        r"/metrics",
        r"/trace",
        r"/flyway",
        r"/liquibase",
    ]
    
    for pattern in debug_patterns:
        if re.search(pattern, path, re.IGNORECASE):
            return True
    
    return False


def build_application_map(
    urls: List[str],
    methods: List[str],
    responses: Dict[str, Any] = None,
    base_url: str = "",
) -> ApplicationMap:
    """Build application map from discovered URLs"""
    
    app_map = ApplicationMap(base_url=base_url)
    
    if responses is None:
        responses = {}
    
    for i, url in enumerate(urls):
        method = methods[i] if i < len(methods) else "GET"
        
        route = RoutePattern(
            path=url,
            method=method.upper(),
            category=categorize_route(url),
            is_sensitive=is_sensitive_route(url),
            parent_route=extract_parent_route(url),
        )
        
        app_map.routes.append(route)
        
        if is_sensitive_route(url):
            app_map.sensitive_routes.append(url)
        
        if is_api_endpoint(url):
            app_map.api_endpoints.append(url)
        
        if is_admin_route(url):
            app_map.admin_routes.append(url)
        
        if is_debug_endpoint(url):
            app_map.debug_endpoints.append(url)
    
    app_map.auth_mechanisms = detect_auth_mechanisms(urls, responses)
    
    return app_map


def extract_parent_route(path: str) -> Optional[str]:
    """Extract parent route from full path"""
    parts = path.strip("/").split("/")
    if len(parts) > 1:
        return "/" + "/".join(parts[:-1])
    return None


def detect_auth_mechanisms(
    urls: List[str],
    responses: Dict[str, Any],
) -> List[AuthMechanism]:
    """Detect authentication mechanisms from endpoints"""
    auth_mechanisms = []
    
    auth_keywords = {
        "bearer": ["/token", "/oauth", "/jwt"],
        "basic": ["/basic", "/auth/basic"],
        "cookie": ["/session", "/sess", "/login"],
        "form": ["/login", "/signin", "/auth"],
    }
    
    for url in urls:
        url_lower = url.lower()
        
        for auth_type, keywords in auth_keywords.items():
            if any(k in url_lower for k in keywords):
                strength = "weak" if auth_type in ["cookie", "form"] else "medium"
                
                auth_mech = AuthMechanism(
                    type=auth_type,
                    endpoint=url,
                    strength=strength,
                )
                auth_mechanisms.append(auth_mech)
                break
    
    return auth_mechanisms


def get_priority_routes(app_map: ApplicationMap) -> List[RoutePattern]:
    """Get routes prioritized by security relevance"""
    priority_routes = []
    
    priority_order = ["debug", "admin", "auth", "data", "api", "user", "static", "unknown"]
    
    for category in priority_order:
        category_routes = [r for r in app_map.routes if r.category == category]
        priority_routes.extend(category_routes)
    
    return priority_routes


def generate_route_inference(app_map: ApplicationMap) -> Dict[str, List[str]]:
    """Generate inferred routes based on patterns"""
    inferred = defaultdict(list)
    
    admin_base = set()
    api_base = set()
    
    for route in app_map.admin_routes:
        parts = route.strip("/").split("/")
        if len(parts) >= 2:
            admin_base.add("/" + parts[0])
    
    for route in app_map.api_endpoints:
        parts = route.strip("/").split("/")
        if len(parts) >= 2:
            api_base.add("/" + parts[0])
    
    for base in admin_base:
        inferred["admin_variations"].extend([
            f"{base}/users",
            f"{base}/config",
            f"{base}/settings",
            f"{base}/logs",
        ])
    
    for base in api_base:
        inferred["api_variations"].extend([
            f"{base}/users",
            f"{base}/items",
            f"{base}/search",
        ])
    
    return dict(inferred)


def get_security_summary(app_map: ApplicationMap) -> Dict[str, Any]:
    """Get security-focused summary of application"""
    return {
        "total_routes": len(app_map.routes),
        "sensitive_routes": len(app_map.sensitive_routes),
        "debug_endpoints": len(app_map.debug_endpoints),
        "admin_routes": len(app_map.admin_routes),
        "api_endpoints": len(app_map.api_endpoints),
        "auth_mechanisms": [a.type for a in app_map.auth_mechanisms],
        "top_categories": get_category_counts(app_map.routes),
    }


def get_category_counts(routes: List[RoutePattern]) -> Dict[str, int]:
    """Get count of routes per category"""
    counts = defaultdict(int)
    for route in routes:
        counts[route.category] += 1
    return dict(counts)