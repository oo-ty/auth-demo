#!/usr/bin/env python3
"""
Cross-Namespace Authentication with Kong API Gateway Demo (2026 Standards)

This demo simulates the authentication flow WITH Kong Gateways:
1. Customer login via External IAM (Direct JWT response - no auth code)
2. Request goes through Kong Gateway A -> Kong Gateway B -> Agent Service B
3. Kong handles JWT validation and adds service tokens for cross-namespace calls
4. Agent A (Namespace A) processes request, calls internal service
5. Results propagate back through the stack

Key differences from demo.py:
- Kong Gateways centralize auth for each namespace
- External IAM returns JWT directly (Resource Owner Password / Direct Token flow)
- Kong plugins handle JWT validation, rate limiting, and service auth
- Cross-namespace calls go through Kong-to-Kong with service tokens

Run: python demo_kong.py
"""

import threading
import queue
import time
import json
import uuid
import hashlib
import base64
import secrets
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List
from enum import Enum
from datetime import datetime, timedelta
import logging

# Configure logging with colors for different components
class ColoredFormatter(logging.Formatter):
    COLORS = {
        'Customer': '\033[96m',       # Cyan
        'WebApp': '\033[94m',         # Blue
        'ExternalIAM': '\033[95m',    # Magenta
        'InternalIAM': '\033[93m',    # Yellow
        'KongA': '\033[38;5;208m',    # Orange
        'KongB': '\033[38;5;214m',    # Light Orange
        'AgentB': '\033[92m',         # Green
        'AgentA': '\033[91m',         # Red
        'ServiceA2': '\033[97m',      # White
        'RESET': '\033[0m',
    }
    
    def format(self, record):
        component = getattr(record, 'component', 'Unknown')
        color = self.COLORS.get(component, '')
        reset = self.COLORS['RESET']
        record.msg = f"{color}[{component}]{reset} {record.msg}"
        return super().format(record)

handler = logging.StreamHandler()
handler.setFormatter(ColoredFormatter('%(asctime)s %(message)s', datefmt='%H:%M:%S'))
logger = logging.getLogger('auth_demo_kong')
logger.addHandler(handler)
logger.setLevel(logging.INFO)

def log(component: str, message: str, step: Optional[int] = None):
    """Log with component context and optional step number."""
    step_prefix = f"[Step {step}] " if step else ""
    logger.info(f"{step_prefix}{message}", extra={'component': component})


# ============================================================================
# Data Models
# ============================================================================

@dataclass
class Token:
    """Represents an OAuth token (access, ID, or service token)."""
    token_id: str
    issuer: str
    subject: str
    audience: List[str]
    scopes: List[str]
    expires_at: datetime
    issued_at: datetime = field(default_factory=datetime.now)
    claims: Dict[str, Any] = field(default_factory=dict)
    token_type: str = "Bearer"
    
    def to_jwt_mock(self) -> str:
        """Generate a mock JWT-like string (base64 encoded for demo)."""
        payload = {
            "iss": self.issuer,
            "sub": self.subject,
            "aud": self.audience,
            "scope": " ".join(self.scopes),
            "exp": self.expires_at.isoformat(),
            "iat": self.issued_at.isoformat(),
            "jti": self.token_id,
            **self.claims
        }
        encoded = base64.b64encode(json.dumps(payload).encode()).decode()
        return f"eyJ.{encoded}.sig"
    
    def is_valid(self) -> bool:
        return datetime.now() < self.expires_at
    
    def has_scope(self, scope: str) -> bool:
        return scope in self.scopes
    
    def has_audience(self, aud: str) -> bool:
        return aud in self.audience


@dataclass
class GatewayRequest:
    """Request passing through Kong Gateway."""
    request_id: str
    method: str
    path: str
    headers: Dict[str, str]
    body: Dict[str, Any]
    # Enriched by gateway
    validated_token: Optional[Dict] = None
    user_context: Optional[Dict] = None
    rate_limit_remaining: int = 100


@dataclass 
class ServiceRequest:
    """Request passed between services (after gateway processing)."""
    request_id: str
    payload: Dict[str, Any]
    user_context: Optional[Dict[str, Any]] = None
    service_token: Optional[str] = None
    customer_token: Optional[str] = None
    source_service: Optional[str] = None
    target_service: Optional[str] = None
    # Kong-specific headers
    x_kong_request_id: Optional[str] = None
    x_consumer_id: Optional[str] = None


@dataclass
class ServiceResponse:
    """Response from services."""
    request_id: str
    success: bool
    data: Dict[str, Any]
    error: Optional[str] = None
    status_code: int = 200


# ============================================================================
# Mock IAM Services
# ============================================================================

class ExternalIAM(threading.Thread):
    """
    External IAM Service - Returns JWT directly (no auth code exchange).
    Simulates Resource Owner Password Credentials or Direct Token Grant.
    """
    
    def __init__(self):
        super().__init__(name="ExternalIAM", daemon=True)
        self.users_db = {
            "customer@example.com": {
                "password_hash": hashlib.sha256("SecurePass123!".encode()).hexdigest(),
                "user_id": "user-12345",
                "name": "Alice Customer",
                "allowed_scopes": ["openid", "profile", "chatbot:access", "agent:invoke"],
                "roles": ["customer", "chatbot_user"]
            }
        }
        # Public keys for JWT validation (mock - in reality would be JWKS endpoint)
        self.jwks = {"keys": [{"kid": "key-1", "kty": "RSA", "use": "sig"}]}
        self.running = True
    
    def authenticate_direct(self, username: str, password: str, 
                            requested_scopes: List[str]) -> Optional[tuple]:
        """
        Direct authentication - returns JWT tokens immediately.
        No auth code intermediate step.
        """
        log("ExternalIAM", f"Direct token request for: {username}", step=3)
        
        user = self.users_db.get(username)
        if not user:
            log("ExternalIAM", "❌ User not found")
            return None
            
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        if password_hash != user["password_hash"]:
            log("ExternalIAM", "❌ Invalid password")
            return None
        
        log("ExternalIAM", "✓ Credentials validated", step=4)
        
        # Filter to allowed scopes
        granted_scopes = [s for s in requested_scopes if s in user["allowed_scopes"]]
        
        now = datetime.now()
        
        # Issue Access Token directly
        access_token = Token(
            token_id=str(uuid.uuid4()),
            issuer="https://external-iam.example.com",
            subject=user["user_id"],
            audience=["kong-gateway-a", "kong-gateway-b", "api-services"],
            scopes=granted_scopes,
            expires_at=now + timedelta(minutes=30),
            claims={
                "name": user["name"], 
                "email": username,
                "roles": user["roles"],
                "kid": "key-1"  # Key ID for JWT validation
            }
        )
        
        # Issue ID Token
        id_token = Token(
            token_id=str(uuid.uuid4()),
            issuer="https://external-iam.example.com",
            subject=user["user_id"],
            audience=["webapp"],
            scopes=["openid", "profile"],
            expires_at=now + timedelta(minutes=30),
            claims={"name": user["name"], "email": username}
        )
        
        # Issue Refresh Token
        refresh_token = Token(
            token_id=str(uuid.uuid4()),
            issuer="https://external-iam.example.com",
            subject=user["user_id"],
            audience=["external-iam"],
            scopes=["refresh"],
            expires_at=now + timedelta(days=7),
            claims={"original_scopes": granted_scopes}
        )
        
        log("ExternalIAM", f"✓ Tokens issued directly - scopes: {granted_scopes}", step=5)
        log("ExternalIAM", f"  Access Token expires: {access_token.expires_at}")
        log("ExternalIAM", f"  Refresh Token expires: {refresh_token.expires_at}")
        
        return access_token, id_token, refresh_token
    
    def get_jwks(self) -> Dict:
        """Return JWKS for token validation (called by Kong)."""
        return self.jwks
    
    def validate_token(self, token_jwt: str) -> Optional[Dict]:
        """Validate and decode a token (mock JWT validation)."""
        try:
            parts = token_jwt.split('.')
            if len(parts) != 3:
                return None
            payload = json.loads(base64.b64decode(parts[1] + '=='))
            exp = datetime.fromisoformat(payload['exp'])
            if datetime.now() > exp:
                return None
            return payload
        except:
            return None
    
    def run(self):
        while self.running:
            time.sleep(0.1)


class InternalIAM(threading.Thread):
    """
    Internal IAM Service for service-to-service authentication.
    Kong Gateways use this for cross-namespace service tokens.
    """
    
    def __init__(self):
        super().__init__(name="InternalIAM", daemon=True)
        self.running = True
        # Registered Kong instances and services
        self.client_registry = {
            "kong-gateway-a": {
                "spiffe_id": "spiffe://cluster.local/ns/namespace-a/sa/kong-gateway",
                "secret_hash": hashlib.sha256("kong-a-secret".encode()).hexdigest(),
                "allowed_audiences": ["kong-gateway-b", "agent-service-a", "agent-service-b"],
                "allowed_scopes": ["cross-namespace:invoke", "gateway:route", "service:call"]
            },
            "kong-gateway-b": {
                "spiffe_id": "spiffe://cluster.local/ns/namespace-b/sa/kong-gateway",
                "secret_hash": hashlib.sha256("kong-b-secret".encode()).hexdigest(),
                "allowed_audiences": ["kong-gateway-a", "agent-service-a", "agent-service-b"],
                "allowed_scopes": ["cross-namespace:invoke", "gateway:route", "service:call"]
            },
            "agent-service-b": {
                "spiffe_id": "spiffe://cluster.local/ns/namespace-b/sa/agent-b",
                "secret_hash": hashlib.sha256("agent-b-secret".encode()).hexdigest(),
                "allowed_audiences": ["agent-service-a", "kong-gateway-a"],
                "allowed_scopes": ["cross-namespace:invoke", "data:read"]
            }
        }
    
    def get_service_token(self, client_id: str, client_secret: str, 
                          audience: str, scopes: List[str],
                          step: Optional[int] = None) -> Optional[Token]:
        """Issue service token via client_credentials grant."""
        log("InternalIAM", f"Service token request from: {client_id}", step=step)
        log("InternalIAM", f"  Target audience: {audience}")
        
        client = self.client_registry.get(client_id)
        if not client:
            log("InternalIAM", f"❌ Unknown client: {client_id}")
            return None
        
        # Validate secret
        secret_hash = hashlib.sha256(client_secret.encode()).hexdigest()
        if secret_hash != client["secret_hash"]:
            log("InternalIAM", f"❌ Invalid client secret")
            return None
        
        # Validate audience is allowed
        if audience not in client["allowed_audiences"]:
            log("InternalIAM", f"❌ Client not authorized for audience: {audience}")
            return None
        
        # Filter to allowed scopes
        granted_scopes = [s for s in scopes if s in client["allowed_scopes"]]
        if not granted_scopes:
            log("InternalIAM", "❌ No valid scopes granted")
            return None
        
        # Issue service token
        token = Token(
            token_id=str(uuid.uuid4()),
            issuer="https://internal-iam.cluster.local",
            subject=client["spiffe_id"],
            audience=[audience],
            scopes=granted_scopes,
            expires_at=datetime.now() + timedelta(minutes=10),
            claims={
                "client_id": client_id,
                "token_type": "service",
                "namespace": "namespace-b" if "-b" in client_id else "namespace-a"
            }
        )
        
        log("InternalIAM", f"✓ Service token issued: {client_id} -> {audience}")
        return token
    
    def run(self):
        while self.running:
            time.sleep(0.1)


# ============================================================================
# Kong API Gateways
# ============================================================================

class KongGateway(threading.Thread):
    """
    Kong API Gateway - Centralized auth, rate limiting, and routing.
    Each namespace has its own Kong instance.
    """
    
    def __init__(self, name: str, namespace: str, external_iam: ExternalIAM, 
                 internal_iam: InternalIAM, client_id: str, client_secret: str):
        super().__init__(name=name, daemon=True)
        self.gateway_name = name
        self.namespace = namespace
        self.external_iam = external_iam
        self.internal_iam = internal_iam
        self.client_id = client_id
        self.client_secret = client_secret
        self.running = True
        
        # Kong plugins configuration
        self.plugins = {
            "jwt": {"enabled": True, "jwks_uri": "https://external-iam.example.com/.well-known/jwks.json"},
            "rate-limiting": {"enabled": True, "minute": 100, "hour": 1000},
            "request-transformer": {"enabled": True},
            "correlation-id": {"enabled": True},
            "acl": {"enabled": True}
        }
        
        # Route configuration
        self.routes = {
            "/api/v1/chatbot/*": {"service": "agent-service-b", "required_scopes": ["chatbot:access"]},
            "/api/v1/agents/*": {"service": "agent-service-a", "required_scopes": ["agent:invoke"]},
            "/internal/*": {"service": "internal-services", "auth": "service-token-only"}
        }
        
        # Rate limit tracking
        self.rate_limits: Dict[str, Dict] = {}
        
        # Token cache for service tokens
        self.service_token_cache: Dict[str, Token] = {}
    
    def validate_jwt(self, token_jwt: str, required_scopes: List[str]) -> tuple:
        """
        Kong JWT Plugin - Validate incoming JWT.
        Returns (is_valid, token_data, error_message)
        """
        log(self.gateway_name, "JWT Plugin: Validating token")
        
        token_data = self.external_iam.validate_token(token_jwt)
        if not token_data:
            return False, None, "Invalid or expired token"
        
        # Check required scopes
        token_scopes = token_data.get("scope", "").split()
        missing_scopes = [s for s in required_scopes if s not in token_scopes]
        if missing_scopes:
            return False, None, f"Missing required scopes: {missing_scopes}"
        
        # Check audience
        audiences = token_data.get("aud", [])
        if self.client_id not in audiences and "api-services" not in audiences:
            return False, None, f"Invalid audience for {self.gateway_name}"
        
        log(self.gateway_name, f"  ✓ Token valid - user: {token_data.get('name')}")
        return True, token_data, None
    
    def check_rate_limit(self, consumer_id: str) -> tuple:
        """Kong Rate Limiting Plugin."""
        now = datetime.now()
        minute_key = now.strftime("%Y%m%d%H%M")
        
        if consumer_id not in self.rate_limits:
            self.rate_limits[consumer_id] = {}
        
        if minute_key not in self.rate_limits[consumer_id]:
            self.rate_limits[consumer_id][minute_key] = 0
        
        self.rate_limits[consumer_id][minute_key] += 1
        count = self.rate_limits[consumer_id][minute_key]
        limit = self.plugins["rate-limiting"]["minute"]
        
        if count > limit:
            return False, 0
        
        return True, limit - count
    
    def add_correlation_id(self, request: GatewayRequest) -> str:
        """Kong Correlation ID Plugin."""
        if "X-Correlation-ID" not in request.headers:
            correlation_id = f"kong-{uuid.uuid4().hex[:12]}"
            request.headers["X-Correlation-ID"] = correlation_id
        return request.headers["X-Correlation-ID"]
    
    def get_service_token(self, target_audience: str) -> Optional[Token]:
        """Get or refresh service token for cross-namespace calls."""
        cache_key = f"{self.client_id}->{target_audience}"
        
        # Check cache
        if cache_key in self.service_token_cache:
            cached = self.service_token_cache[cache_key]
            if cached.is_valid():
                log(self.gateway_name, f"  Using cached service token for {target_audience}")
                return cached
        
        # Request new token
        token = self.internal_iam.get_service_token(
            client_id=self.client_id,
            client_secret=self.client_secret,
            audience=target_audience,
            scopes=["cross-namespace:invoke", "gateway:route"]
        )
        
        if token:
            self.service_token_cache[cache_key] = token
        
        return token
    
    def process_ingress(self, request: GatewayRequest, required_scopes: List[str],
                        step: Optional[int] = None) -> tuple:
        """
        Process incoming request through Kong plugins.
        Returns (success, enriched_request, error_response)
        """
        log(self.gateway_name, f"Ingress: {request.method} {request.path}", step=step)
        
        # Correlation ID
        correlation_id = self.add_correlation_id(request)
        log(self.gateway_name, f"  Correlation ID: {correlation_id}")
        
        # JWT Validation
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return False, None, ServiceResponse(
                request_id=request.request_id,
                success=False,
                data={},
                error="Missing or invalid Authorization header",
                status_code=401
            )
        
        token_jwt = auth_header.replace("Bearer ", "")
        is_valid, token_data, error = self.validate_jwt(token_jwt, required_scopes)
        
        if not is_valid:
            log(self.gateway_name, f"  ❌ JWT validation failed: {error}")
            return False, None, ServiceResponse(
                request_id=request.request_id,
                success=False,
                data={},
                error=error,
                status_code=403
            )
        
        request.validated_token = token_data
        
        # Rate Limiting
        consumer_id = token_data.get("sub", "anonymous")
        rate_ok, remaining = self.check_rate_limit(consumer_id)
        
        if not rate_ok:
            log(self.gateway_name, f"  ❌ Rate limit exceeded for {consumer_id}")
            return False, None, ServiceResponse(
                request_id=request.request_id,
                success=False,
                data={},
                error="Rate limit exceeded",
                status_code=429
            )
        
        request.rate_limit_remaining = remaining
        log(self.gateway_name, f"  Rate limit: {remaining} remaining")
        
        # Extract user context
        request.user_context = {
            "user_id": token_data.get("sub"),
            "name": token_data.get("name"),
            "email": token_data.get("email"),
            "roles": token_data.get("roles", []),
            "scopes": token_data.get("scope", "").split()
        }
        
        log(self.gateway_name, f"  ✓ Request authorized for: {request.user_context.get('name')}")
        
        return True, request, None
    
    def prepare_cross_namespace_call(self, request: GatewayRequest, 
                                      target_gateway: str, step: Optional[int] = None) -> Optional[GatewayRequest]:
        """Prepare request for cross-namespace routing through another Kong."""
        log(self.gateway_name, f"Preparing cross-namespace call to {target_gateway}", step=step)
        
        # Get service token for target gateway
        service_token = self.get_service_token(target_gateway)
        if not service_token:
            log(self.gateway_name, f"  ❌ Failed to obtain service token")
            return None
        
        # Create new request with service token
        # Build headers with proper string values
        user_id = ""
        scopes_str = ""
        if request.user_context:
            user_id = str(request.user_context.get("user_id", ""))
            scopes_str = " ".join(request.user_context.get("scopes", []))
        
        new_headers: Dict[str, str] = {
            **request.headers,
            "X-Service-Token": f"Bearer {service_token.to_jwt_mock()}",
            "X-Original-Consumer": user_id,
            "X-Source-Gateway": self.gateway_name,
            "X-Forwarded-Scopes": scopes_str
        }
        
        cross_ns_request = GatewayRequest(
            request_id=request.request_id,
            method=request.method,
            path=request.path,
            headers=new_headers,
            body=request.body,
            user_context=request.user_context
        )
        
        log(self.gateway_name, f"  ✓ Added service token for {target_gateway}")
        log(self.gateway_name, f"  Preserving user context: {request.user_context.get('name') if request.user_context else 'N/A'}")
        
        return cross_ns_request
    
    def process_service_token_request(self, request: GatewayRequest, 
                                        required_scopes: List[str],
                                        step: Optional[int] = None) -> tuple:
        """Process incoming request authenticated with service token (cross-namespace)."""
        log(self.gateway_name, f"Processing service token request", step=step)
        
        # Extract service token
        service_token_header = request.headers.get("X-Service-Token", "")
        if not service_token_header.startswith("Bearer "):
            return False, None, "Missing service token"
        
        token_jwt = service_token_header.replace("Bearer ", "")
        
        try:
            parts = token_jwt.split('.')
            token_data = json.loads(base64.b64decode(parts[1] + '=='))
        except:
            return False, None, "Invalid service token format"
        
        # Validate audience
        audiences = token_data.get("aud", [])
        if self.client_id not in audiences and self.gateway_name not in audiences:
            log(self.gateway_name, f"  ❌ Invalid audience: {audiences}")
            return False, None, "Invalid token audience"
        
        # Validate scopes
        token_scopes = token_data.get("scope", "").split()
        if "cross-namespace:invoke" not in token_scopes and "gateway:route" not in token_scopes:
            return False, None, "Missing required scope for cross-namespace call"
        
        log(self.gateway_name, f"  ✓ Service token valid from: {token_data.get('client_id')}")
        
        # Reconstruct user context from headers
        request.user_context = {
            "user_id": request.headers.get("X-Original-Consumer"),
            "source_gateway": request.headers.get("X-Source-Gateway"),
            "original_scopes": request.headers.get("X-Forwarded-Scopes", "").split()
        }
        
        return True, request, None
    
    def run(self):
        while self.running:
            time.sleep(0.1)


# ============================================================================
# Application Services
# ============================================================================

class WebApplication(threading.Thread):
    """
    Web Application (Frontend + BFF) in Namespace A.
    Handles customer login and forwards requests through Kong Gateway.
    """
    
    def __init__(self, external_iam: ExternalIAM, kong_gateway: KongGateway):
        super().__init__(name="WebApp", daemon=True)
        self.external_iam = external_iam
        self.kong = kong_gateway
        self.sessions: Dict[str, Dict] = {}
        self.running = True
    
    def login(self, username: str, password: str) -> Optional[str]:
        """Handle customer login - Direct JWT response (no auth code)."""
        log("WebApp", f"Customer login initiated", step=1)
        
        requested_scopes = ["openid", "profile", "chatbot:access", "agent:invoke"]
        
        log("WebApp", "Requesting tokens from External IAM", step=2)
        log("Customer", f"Submitting credentials")
        
        # Direct token request - no auth code intermediate step
        tokens = self.external_iam.authenticate_direct(
            username, password, requested_scopes
        )
        
        if not tokens:
            log("WebApp", "❌ Authentication failed")
            return None
        
        access_token, id_token, refresh_token = tokens
        
        # Create session
        session_id = secrets.token_urlsafe(32)
        self.sessions[session_id] = {
            "access_token": access_token,
            "id_token": id_token,
            "refresh_token": refresh_token,
            "user": access_token.claims
        }
        
        log("WebApp", f"✓ Session established for: {access_token.claims.get('name')}", step=6)
        log("WebApp", f"  Tokens received directly (no auth code exchange)")
        return session_id
    
    def create_api_request(self, session_id: str, path: str, 
                            action: Dict) -> Optional[GatewayRequest]:
        """Create API request to be sent through Kong Gateway."""
        session = self.sessions.get(session_id)
        if not session:
            log("WebApp", "❌ Invalid session")
            return None
        
        access_token = session["access_token"]
        
        log("Customer", f"Triggering action: {action.get('action')}", step=7)
        log("WebApp", f"Creating API request to Kong Gateway", step=8)
        
        request = GatewayRequest(
            request_id=str(uuid.uuid4()),
            method="POST",
            path=path,
            headers={
                "Authorization": f"Bearer {access_token.to_jwt_mock()}",
                "Content-Type": "application/json"
            },
            body=action
        )
        
        return request
    
    def run(self):
        while self.running:
            time.sleep(0.1)


class AgentServiceB(threading.Thread):
    """
    Agent Service B in Namespace B.
    Receives pre-validated requests from Kong Gateway B.
    """
    
    def __init__(self):
        super().__init__(name="AgentB", daemon=True)
        self.running = True
        self.service_id = "agent-service-b"
    
    def process_request(self, request: GatewayRequest) -> tuple:
        """
        Process request that has been pre-validated by Kong.
        Kong has already validated JWT and added user context.
        """
        log("AgentB", f"Received pre-validated request from Kong", step=12)
        log("AgentB", f"  User: {request.user_context.get('name') if request.user_context else 'N/A'}")
        log("AgentB", f"  Correlation ID: {request.headers.get('X-Correlation-ID')}")
        
        # Analyze request
        needs_namespace_a = request.body.get("requires_namespace_a", True)
        
        if needs_namespace_a:
            log("AgentB", "Request requires Agent Service A (Namespace A)", step=13)
            log("AgentB", "Will route back through Kong for cross-namespace call")
            
            # Return indication that cross-namespace call is needed
            return True, {
                "needs_cross_namespace": True,
                "target": "agent-service-a",
                "payload": request.body,
                "user_context": request.user_context
            }
        
        # Process locally
        return False, {"result": "Processed locally in Namespace B"}
    
    def receive_cross_namespace_response(self, response: ServiceResponse) -> ServiceResponse:
        """Handle response from cross-namespace call."""
        log("AgentB", "Received cross-namespace response", step=22)
        return response
    
    def run(self):
        while self.running:
            time.sleep(0.1)


class AgentServiceA(threading.Thread):
    """
    Agent Service A in Namespace A.
    Receives requests from Kong Gateway A (could be cross-namespace).
    """
    
    def __init__(self):
        super().__init__(name="AgentA", daemon=True)
        self.running = True
        self.service_id = "agent-service-a"
    
    def process_request(self, request: GatewayRequest) -> Optional[ServiceRequest]:
        """Process request (already validated by Kong Gateway A)."""
        log("AgentA", "Processing request from Kong Gateway A", step=18)
        
        user_context = request.user_context or {}
        log("AgentA", f"  Original user: {user_context.get('user_id', 'N/A')}")
        log("AgentA", f"  Source gateway: {user_context.get('source_gateway', 'direct')}")
        
        # Determine if internal service call is needed
        log("AgentA", "Need to call Internal Service A2", step=19)
        
        # Create internal request (no additional auth - same namespace)
        internal_request = ServiceRequest(
            request_id=request.request_id,
            payload={
                **request.body,
                "processed_by": "agent-a",
                "user_context": user_context
            },
            source_service="agent-service-a",
            target_service="internal-service-a2",
            x_kong_request_id=request.headers.get("X-Correlation-ID")
        )
        
        return internal_request
    
    def receive_response(self, response: ServiceResponse) -> ServiceResponse:
        """Process response from internal service."""
        log("AgentA", "Received response from Service A2", step=21)
        return response
    
    def run(self):
        while self.running:
            time.sleep(0.1)


class InternalServiceA2(threading.Thread):
    """
    Internal Service A2 in Namespace A.
    No additional auth needed - Kong + service mesh handle security.
    """
    
    def __init__(self):
        super().__init__(name="ServiceA2", daemon=True)
        self.running = True
    
    def process_request(self, request: ServiceRequest) -> ServiceResponse:
        """Process business logic."""
        log("ServiceA2", "Received request (intra-namespace - trusted via Kong/mTLS)")
        log("ServiceA2", f"  Request from: {request.source_service}")
        log("ServiceA2", f"  Kong Request ID: {request.x_kong_request_id}")
        
        user_ctx = request.payload.get('user_context', {})
        log("ServiceA2", f"  Original user: {user_ctx.get('user_id', 'N/A')}")
        
        log("ServiceA2", "Processing business logic...", step=20)
        time.sleep(0.3)
        
        result = {
            "status": "completed",
            "message": f"Successfully processed: {request.payload.get('action')}",
            "data": {
                "request_id": request.request_id,
                "processed_at": datetime.now().isoformat(),
                "result": "The answer to your question is 42.",
                "kong_trace_id": request.x_kong_request_id
            },
            "audit": {
                "processed_by": "internal-service-a2",
                "user_id": user_ctx.get("user_id"),
                "action": request.payload.get("action")
            }
        }
        
        log("ServiceA2", "✓ Processing complete")
        
        return ServiceResponse(
            request_id=request.request_id,
            success=True,
            data=result
        )
    
    def run(self):
        while self.running:
            time.sleep(0.1)


# ============================================================================
# Demo Orchestrator
# ============================================================================

def run_demo():
    """Run the complete Kong Gateway authentication flow demo."""
    
    print("\n" + "="*80)
    print(" Cross-Namespace Auth with Kong API Gateway Demo (2026 Standards)")
    print("="*80 + "\n")
    
    # Initialize IAM services
    print("Initializing services...\n")
    
    external_iam = ExternalIAM()
    internal_iam = InternalIAM()
    
    # Initialize Kong Gateways (one per namespace)
    kong_a = KongGateway(
        name="KongA",
        namespace="namespace-a",
        external_iam=external_iam,
        internal_iam=internal_iam,
        client_id="kong-gateway-a",
        client_secret="kong-a-secret"
    )
    
    kong_b = KongGateway(
        name="KongB",
        namespace="namespace-b",
        external_iam=external_iam,
        internal_iam=internal_iam,
        client_id="kong-gateway-b",
        client_secret="kong-b-secret"
    )
    
    # Initialize application services
    web_app = WebApplication(external_iam, kong_a)
    agent_b = AgentServiceB()
    agent_a = AgentServiceA()
    service_a2 = InternalServiceA2()
    
    # Start all services
    services = [external_iam, internal_iam, kong_a, kong_b, web_app, agent_b, agent_a, service_a2]
    for service in services:
        service.start()
    
    time.sleep(0.5)
    
    print("-"*80)
    print(" PHASE 1: Customer Authentication (Direct JWT - No Auth Code)")
    print("-"*80 + "\n")
    
    # Customer login
    session_id = web_app.login(
        username="customer@example.com",
        password="SecurePass123!"
    )
    
    if not session_id:
        print("\n❌ Login failed!")
        return
    
    print("\n" + "-"*80)
    print(" PHASE 2: Request Through Kong Gateway B (Namespace B)")
    print("-"*80 + "\n")
    
    time.sleep(0.5)
    
    # Customer triggers chatbot action
    chatbot_action = {
        "action": "ask_question",
        "query": "What is the meaning of life?",
        "requires_namespace_a": True
    }
    
    # WebApp creates request for Kong
    gateway_request = web_app.create_api_request(
        session_id, 
        "/api/v1/chatbot/query",
        chatbot_action
    )
    
    if not gateway_request:
        print("\n❌ Failed to create request!")
        return
    
    time.sleep(0.3)
    
    # Kong Gateway B processes ingress
    log("WebApp", "Sending request to Kong Gateway B", step=9)
    success, processed_request, error = kong_b.process_ingress(
        gateway_request, 
        required_scopes=["chatbot:access"],
        step=10
    )
    
    if not success:
        print(f"\n❌ Kong Gateway B rejected request: {error}")
        return
    
    time.sleep(0.3)
    
    # Kong routes to Agent B
    log("KongB", "Routing to Agent Service B", step=11)
    
    # Agent B processes
    needs_cross_ns, agent_b_result = agent_b.process_request(processed_request)
    
    if needs_cross_ns:
        print("\n" + "-"*80)
        print(" PHASE 3: Cross-Namespace Call (Kong B -> Kong A)")
        print("-"*80 + "\n")
        
        time.sleep(0.3)
        
        # Kong B prepares cross-namespace call
        cross_ns_request = kong_b.prepare_cross_namespace_call(
            processed_request,
            target_gateway="kong-gateway-a",
            step=14
        )
        
        if not cross_ns_request:
            print("\n❌ Failed to prepare cross-namespace request!")
            return
        
        time.sleep(0.3)
        
        # Update request body with agent B's processed info
        cross_ns_request.body = agent_b_result["payload"]
        
        # Kong A receives and validates service token
        log("KongB", "Sending request to Kong Gateway A", step=15)
        success, validated_request, error = kong_a.process_service_token_request(
            cross_ns_request,
            required_scopes=["cross-namespace:invoke"],
            step=16
        )
        
        if not success:
            print(f"\n❌ Kong Gateway A rejected request: {error}")
            return
        
        time.sleep(0.3)
        
        # Kong A routes to Agent A
        log("KongA", "Routing to Agent Service A (intra-namespace)", step=17)
        
        print("\n" + "-"*80)
        print(" PHASE 4: Intra-Namespace Processing (Namespace A)")
        print("-"*80 + "\n")
        
        # Agent A processes
        request_to_a2 = agent_a.process_request(validated_request)
        
        if not request_to_a2:
            print("\n❌ Agent A processing failed!")
            return
        
        time.sleep(0.3)
        
        # Internal Service A2 processes
        response_from_a2 = service_a2.process_request(request_to_a2)
        
        print("\n" + "-"*80)
        print(" PHASE 5: Response Propagation")
        print("-"*80 + "\n")
        
        # Propagate responses back
        response_at_a = agent_a.receive_response(response_from_a2)
        
        log("KongA", "Returning response to Kong Gateway B", step=23)
        log("KongB", "Returning response to Agent Service B", step=24)
        
        response_at_b = agent_b.receive_cross_namespace_response(response_at_a)
        
        log("KongB", "Returning response to WebApp", step=25)
        log("WebApp", "Displaying result to customer", step=26)
    else:
        # If no cross-namespace call needed, create local response
        response_at_b = ServiceResponse(
            request_id=gateway_request.request_id,
            success=True,
            data=agent_b_result
        )
    
    print("\n" + "-"*80)
    print(" DEMO COMPLETE - Final Result")
    print("-"*80)
    print(f"\n✅ Success: {response_at_b.success}")
    print(f"📋 Result: {json.dumps(response_at_b.data, indent=2)}")
    
    print("\n" + "="*80)
    print(" Kong Gateway Authentication Flow Summary")
    print("="*80)
    print("""
    ┌─────────────────────────────────────────────────────────────────────────────┐
    │  Key Differences from Standard Flow:                                        │
    ├─────────────────────────────────────────────────────────────────────────────┤
    │  1. External IAM returns JWT directly (no auth code exchange)               │
    │  2. Kong Gateway B handles JWT validation centrally (JWT Plugin)            │
    │  3. Kong adds correlation ID, rate limiting, request transformation         │
    │  4. Cross-namespace: Kong B gets service token from Internal IAM            │
    │  5. Kong A validates service token (gateway-to-gateway trust)               │
    │  6. User context propagated via X-Original-Consumer header                  │
    │  7. Intra-namespace calls trusted via Kong + mTLS                           │
    └─────────────────────────────────────────────────────────────────────────────┘
    
    ┌─────────────────────────────────────────────────────────────────────────────┐
    │  Kong Gateway Benefits:                                                     │
    ├─────────────────────────────────────────────────────────────────────────────┤
    │  • Centralized auth - services don't need to validate JWTs                  │
    │  • Rate limiting at the edge                                                │
    │  • Request/response transformation                                          │
    │  • Correlation IDs for distributed tracing                                  │
    │  • Service token caching for cross-namespace calls                          │
    │  • Consistent security policies across all services                         │
    └─────────────────────────────────────────────────────────────────────────────┘
    """)
    
    # Cleanup
    for service in services:
        service.running = False


if __name__ == "__main__":
    run_demo()
