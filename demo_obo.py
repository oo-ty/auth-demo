#!/usr/bin/env python3
"""
Cross-Namespace Authentication with On-Behalf-Of (OBO) Flow Demo (2026 Standards)

This demo implements the OAuth 2.0 Token Exchange (RFC 8693) for OBO scenarios:
1. Customer login via External IAM (Direct JWT)
2. Request goes through Kong Gateway B
3. Agent B exchanges customer token for OBO token ("Agent B acting on behalf of Alice")
4. Cross-namespace call uses OBO token (preserves delegation chain)
5. Agent A can see the full delegation chain in the token

Key difference from demo_kong.py:
- Services obtain OBO tokens that cryptographically prove delegation
- Token contains actor chain: who is acting on behalf of whom
- Each hop in the chain is recorded in the token

Run: python demo_obo.py
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
        'TokenExchange': '\033[38;5;141m',  # Purple
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
logger = logging.getLogger('auth_demo_obo')
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
class ActorChain:
    """Represents the delegation chain in OBO tokens."""
    subject: str              # Original user (e.g., "user-12345")
    subject_name: str         # Human readable (e.g., "Alice Customer")
    actors: List[Dict[str, str]] = field(default_factory=list)  # Chain of actors
    
    def add_actor(self, actor_id: str, actor_type: str, actor_name: str):
        """Add an actor to the delegation chain."""
        self.actors.append({
            "actor_id": actor_id,
            "actor_type": actor_type,
            "actor_name": actor_name,
            "delegated_at": datetime.now().isoformat()
        })
    
    def to_claim(self) -> Dict:
        """Convert to JWT 'act' claim (RFC 8693)."""
        if not self.actors:
            return {}
        
        # Build nested actor chain per RFC 8693
        # { "act": { "sub": "agent-b", "act": { "sub": "kong-b" } } }
        result = None
        for actor in reversed(self.actors):
            if result is None:
                result = {"sub": actor["actor_id"], "act_type": actor["actor_type"]}
            else:
                result = {"sub": actor["actor_id"], "act_type": actor["actor_type"], "act": result}
        
        return {"act": result} if result else {}
    
    def get_chain_description(self) -> str:
        """Human-readable delegation chain."""
        if not self.actors:
            return f"{self.subject_name}"
        
        chain = f"{self.subject_name}"
        for actor in self.actors:
            chain += f" → {actor['actor_name']}"
        return chain


@dataclass
class Token:
    """Represents an OAuth token with OBO support."""
    token_id: str
    issuer: str
    subject: str              # The original subject (user)
    audience: List[str]
    scopes: List[str]
    expires_at: datetime
    issued_at: datetime = field(default_factory=datetime.now)
    claims: Dict[str, Any] = field(default_factory=dict)
    token_type: str = "Bearer"
    
    # OBO-specific fields
    actor_chain: Optional[ActorChain] = None
    is_obo_token: bool = False
    may_act: Optional[List[str]] = None  # Services allowed to act on behalf
    
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
        
        # Add OBO claims if present
        if self.actor_chain:
            payload.update(self.actor_chain.to_claim())
            payload["delegation_chain"] = [
                a["actor_name"] for a in self.actor_chain.actors
            ]
        
        if self.is_obo_token:
            payload["token_type"] = "obo"
        
        if self.may_act:
            payload["may_act"] = {"sub": self.may_act}
        
        encoded = base64.b64encode(json.dumps(payload).encode()).decode()
        return f"eyJ.{encoded}.sig"
    
    def is_valid(self) -> bool:
        return datetime.now() < self.expires_at
    
    def has_scope(self, scope: str) -> bool:
        return scope in self.scopes
    
    def has_audience(self, aud: str) -> bool:
        return aud in self.audience
    
    def get_actor_description(self) -> str:
        """Get human-readable description of who is acting."""
        if self.actor_chain:
            return self.actor_chain.get_chain_description()
        return self.claims.get("name", self.subject)


@dataclass
class GatewayRequest:
    """Request passing through Kong Gateway."""
    request_id: str
    method: str
    path: str
    headers: Dict[str, str]
    body: Dict[str, Any]
    validated_token: Optional[Dict] = None
    user_context: Optional[Dict] = None
    obo_token: Optional[Token] = None  # OBO token if present
    rate_limit_remaining: int = 100


@dataclass 
class ServiceRequest:
    """Request passed between services."""
    request_id: str
    payload: Dict[str, Any]
    user_context: Optional[Dict[str, Any]] = None
    obo_token: Optional[Token] = None  # The OBO token proving delegation
    source_service: Optional[str] = None
    target_service: Optional[str] = None
    correlation_id: Optional[str] = None


@dataclass
class ServiceResponse:
    """Response from services."""
    request_id: str
    success: bool
    data: Dict[str, Any]
    error: Optional[str] = None
    status_code: int = 200


# ============================================================================
# Token Exchange Service (RFC 8693)
# ============================================================================

class TokenExchangeService(threading.Thread):
    """
    OAuth 2.0 Token Exchange Service (RFC 8693).
    Handles On-Behalf-Of token exchange requests.
    
    This is the key difference from demo_kong.py:
    - Services exchange customer tokens for OBO tokens
    - OBO tokens contain the actor chain showing delegation
    """
    
    def __init__(self, external_iam: 'ExternalIAM'):
        super().__init__(name="TokenExchange", daemon=True)
        self.external_iam = external_iam
        self.running = True
        
        # Registered services that can perform token exchange
        self.registered_actors = {
            "kong-gateway-b": {
                "name": "Kong Gateway B",
                "type": "gateway",
                "allowed_to_impersonate": True,
                "max_delegation_depth": 3
            },
            "agent-service-b": {
                "name": "Agent Service B",
                "type": "service",
                "allowed_to_impersonate": True,
                "max_delegation_depth": 3
            },
            "kong-gateway-a": {
                "name": "Kong Gateway A", 
                "type": "gateway",
                "allowed_to_impersonate": True,
                "max_delegation_depth": 3
            },
            "agent-service-a": {
                "name": "Agent Service A",
                "type": "service",
                "allowed_to_impersonate": True,
                "max_delegation_depth": 2
            }
        }
    
    def exchange_token(self, 
                       subject_token: str,
                       actor_id: str,
                       actor_secret: str,
                       requested_token_type: str = "urn:ietf:params:oauth:token-type:access_token",
                       audience: Optional[List[str]] = None,
                       scopes: Optional[List[str]] = None,
                       step: Optional[int] = None) -> Optional[Token]:
        """
        RFC 8693 Token Exchange for OBO.
        
        Parameters:
        - subject_token: The original token (customer's or previous OBO token)
        - actor_id: The service requesting to act on behalf
        - actor_secret: Service credentials
        - audience: Target audience for new token
        - scopes: Requested scopes (must be subset of original)
        """
        log("TokenExchange", f"OBO Token Exchange Request", step=step)
        log("TokenExchange", f"  Actor: {actor_id}")
        log("TokenExchange", f"  Requested audience: {audience}")
        
        # Validate actor is registered
        actor_config = self.registered_actors.get(actor_id)
        if not actor_config:
            log("TokenExchange", f"  ❌ Unknown actor: {actor_id}")
            return None
        
        if not actor_config["allowed_to_impersonate"]:
            log("TokenExchange", f"  ❌ Actor not allowed to impersonate")
            return None
        
        # Validate and decode subject token
        subject_token_data = self.external_iam.validate_token(subject_token)
        if not subject_token_data:
            log("TokenExchange", f"  ❌ Invalid subject token")
            return None
        
        # Check may_act claim if present (authorized actors)
        may_act = subject_token_data.get("may_act", {}).get("sub", [])
        if may_act and actor_id not in may_act:
            log("TokenExchange", f"  ❌ Actor not in may_act list")
            return None
        
        # Build or extend actor chain
        existing_chain = subject_token_data.get("delegation_chain", [])
        
        # Check delegation depth
        if len(existing_chain) >= actor_config["max_delegation_depth"]:
            log("TokenExchange", f"  ❌ Max delegation depth exceeded")
            return None
        
        # Create new actor chain
        subject_id = subject_token_data.get("sub") or "unknown"
        subject_name = subject_token_data.get("name") or "Unknown User"
        actor_chain = ActorChain(
            subject=subject_id,
            subject_name=subject_name
        )
        
        # Add existing actors from chain
        for actor_name in existing_chain:
            actor_chain.actors.append({
                "actor_id": actor_name,
                "actor_type": "service",
                "actor_name": actor_name,
                "delegated_at": "previous"
            })
        
        # Add new actor
        actor_chain.add_actor(
            actor_id=actor_id,
            actor_type=actor_config["type"],
            actor_name=actor_config["name"]
        )
        
        log("TokenExchange", f"  Delegation chain: {actor_chain.get_chain_description()}")
        
        # Determine scopes (must be subset of original)
        original_scopes = subject_token_data.get("scope", "").split()
        if scopes:
            granted_scopes = [s for s in scopes if s in original_scopes]
        else:
            granted_scopes = original_scopes
        
        # Create OBO token
        obo_token = Token(
            token_id=str(uuid.uuid4()),
            issuer="https://token-exchange.example.com",
            subject=subject_id,  # Original subject preserved
            audience=audience or subject_token_data.get("aud", []),
            scopes=granted_scopes,
            expires_at=datetime.now() + timedelta(minutes=15),
            claims={
                "name": subject_token_data.get("name"),
                "email": subject_token_data.get("email"),
                "original_issuer": subject_token_data.get("iss")
            },
            actor_chain=actor_chain,
            is_obo_token=True
        )
        
        log("TokenExchange", f"  ✓ OBO token issued")
        log("TokenExchange", f"  Subject: {obo_token.subject} ({subject_token_data.get('name')})")
        log("TokenExchange", f"  Acting as: {actor_config['name']}")
        
        return obo_token
    
    def run(self):
        while self.running:
            time.sleep(0.1)


# ============================================================================
# Mock IAM Services
# ============================================================================

class ExternalIAM(threading.Thread):
    """External IAM Service - Returns JWT directly with may_act claim."""
    
    def __init__(self):
        super().__init__(name="ExternalIAM", daemon=True)
        self.users_db = {
            "customer@example.com": {
                "password_hash": hashlib.sha256("SecurePass123!".encode()).hexdigest(),
                "user_id": "user-12345",
                "name": "Alice Customer",
                "allowed_scopes": ["openid", "profile", "chatbot:access", "agent:invoke"],
                "roles": ["customer", "chatbot_user"],
                # Services that can act on behalf of this user
                "may_act": ["kong-gateway-b", "agent-service-b", "kong-gateway-a", "agent-service-a"]
            }
        }
        self.running = True
    
    def authenticate_direct(self, username: str, password: str, 
                            requested_scopes: List[str]) -> Optional[tuple]:
        """Direct authentication - returns JWT with may_act claim."""
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
        
        granted_scopes = [s for s in requested_scopes if s in user["allowed_scopes"]]
        now = datetime.now()
        
        # Issue Access Token WITH may_act claim
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
                "roles": user["roles"]
            },
            may_act=user["may_act"]  # Authorized actors
        )
        
        id_token = Token(
            token_id=str(uuid.uuid4()),
            issuer="https://external-iam.example.com",
            subject=user["user_id"],
            audience=["webapp"],
            scopes=["openid", "profile"],
            expires_at=now + timedelta(minutes=30),
            claims={"name": user["name"], "email": username}
        )
        
        refresh_token = Token(
            token_id=str(uuid.uuid4()),
            issuer="https://external-iam.example.com",
            subject=user["user_id"],
            audience=["external-iam"],
            scopes=["refresh"],
            expires_at=now + timedelta(days=7),
            claims={"original_scopes": granted_scopes}
        )
        
        log("ExternalIAM", f"✓ Tokens issued with may_act claim", step=5)
        log("ExternalIAM", f"  User: {user['name']}")
        log("ExternalIAM", f"  May act: {user['may_act']}")
        
        return access_token, id_token, refresh_token
    
    def validate_token(self, token_jwt: str) -> Optional[Dict]:
        """Validate and decode a token."""
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
    """Internal IAM for basic service-to-service auth (non-OBO scenarios)."""
    
    def __init__(self):
        super().__init__(name="InternalIAM", daemon=True)
        self.running = True
        self.client_registry = {
            "kong-gateway-a": {"secret_hash": hashlib.sha256("kong-a-secret".encode()).hexdigest()},
            "kong-gateway-b": {"secret_hash": hashlib.sha256("kong-b-secret".encode()).hexdigest()},
            "agent-service-b": {"secret_hash": hashlib.sha256("agent-b-secret".encode()).hexdigest()},
            "agent-service-a": {"secret_hash": hashlib.sha256("agent-a-secret".encode()).hexdigest()}
        }
    
    def validate_service_credentials(self, client_id: str, client_secret: str) -> bool:
        """Validate service credentials (used for token exchange requests)."""
        client = self.client_registry.get(client_id)
        if not client:
            return False
        return hashlib.sha256(client_secret.encode()).hexdigest() == client["secret_hash"]
    
    def run(self):
        while self.running:
            time.sleep(0.1)


# ============================================================================
# Kong API Gateways (with OBO support)
# ============================================================================

class KongGateway(threading.Thread):
    """Kong API Gateway with On-Behalf-Of token exchange support."""
    
    def __init__(self, name: str, namespace: str, external_iam: ExternalIAM,
                 token_exchange: TokenExchangeService, client_id: str, client_secret: str):
        super().__init__(name=name, daemon=True)
        self.gateway_name = name
        self.namespace = namespace
        self.external_iam = external_iam
        self.token_exchange = token_exchange
        self.client_id = client_id
        self.client_secret = client_secret
        self.running = True
        self.rate_limits: Dict[str, Dict] = {}
    
    def validate_jwt(self, token_jwt: str, required_scopes: List[str]) -> tuple:
        """Validate incoming JWT (customer or OBO token)."""
        log(self.gateway_name, "JWT Plugin: Validating token")
        
        token_data = self.external_iam.validate_token(token_jwt)
        if not token_data:
            return False, None, "Invalid or expired token"
        
        # Check if it's an OBO token
        is_obo = token_data.get("token_type") == "obo"
        if is_obo:
            log(self.gateway_name, f"  Token type: OBO (delegated)")
            delegation_chain = token_data.get("delegation_chain", [])
            if delegation_chain:
                log(self.gateway_name, f"  Delegation: {' → '.join(delegation_chain)}")
        else:
            log(self.gateway_name, f"  Token type: Direct (customer)")
        
        # Check scopes
        token_scopes = token_data.get("scope", "").split()
        missing_scopes = [s for s in required_scopes if s not in token_scopes]
        if missing_scopes:
            return False, None, f"Missing scopes: {missing_scopes}"
        
        log(self.gateway_name, f"  ✓ Token valid - subject: {token_data.get('name', token_data.get('sub'))}")
        return True, token_data, None
    
    def check_rate_limit(self, consumer_id: str) -> tuple:
        """Rate limiting plugin."""
        now = datetime.now()
        minute_key = now.strftime("%Y%m%d%H%M")
        
        if consumer_id not in self.rate_limits:
            self.rate_limits[consumer_id] = {}
        if minute_key not in self.rate_limits[consumer_id]:
            self.rate_limits[consumer_id][minute_key] = 0
        
        self.rate_limits[consumer_id][minute_key] += 1
        count = self.rate_limits[consumer_id][minute_key]
        limit = 100
        
        return count <= limit, limit - count
    
    def exchange_for_obo_token(self, customer_token: str, target_audience: List[str],
                                step: Optional[int] = None) -> Optional[Token]:
        """Exchange customer token for OBO token."""
        log(self.gateway_name, f"Requesting OBO token exchange", step=step)
        
        obo_token = self.token_exchange.exchange_token(
            subject_token=customer_token,
            actor_id=self.client_id,
            actor_secret=self.client_secret,
            audience=target_audience,
            step=step
        )
        
        return obo_token
    
    def process_ingress(self, request: GatewayRequest, required_scopes: List[str],
                        step: Optional[int] = None) -> tuple:
        """Process incoming request through Kong plugins."""
        log(self.gateway_name, f"Ingress: {request.method} {request.path}", step=step)
        
        # Add correlation ID
        if "X-Correlation-ID" not in request.headers:
            request.headers["X-Correlation-ID"] = f"kong-{uuid.uuid4().hex[:12]}"
        log(self.gateway_name, f"  Correlation ID: {request.headers['X-Correlation-ID']}")
        
        # JWT Validation
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return False, None, ServiceResponse(
                request_id=request.request_id, success=False, data={},
                error="Missing Authorization header", status_code=401
            )
        
        token_jwt = auth_header.replace("Bearer ", "")
        is_valid, token_data, error = self.validate_jwt(token_jwt, required_scopes)
        
        if not is_valid:
            log(self.gateway_name, f"  ❌ JWT validation failed: {error}")
            return False, None, ServiceResponse(
                request_id=request.request_id, success=False, data={},
                error=error, status_code=403
            )
        
        request.validated_token = token_data
        
        # Rate Limiting
        consumer_id = token_data.get("sub", "anonymous")
        rate_ok, remaining = self.check_rate_limit(consumer_id)
        if not rate_ok:
            return False, None, ServiceResponse(
                request_id=request.request_id, success=False, data={},
                error="Rate limit exceeded", status_code=429
            )
        request.rate_limit_remaining = remaining
        
        # Extract user context
        request.user_context = {
            "user_id": token_data.get("sub"),
            "name": token_data.get("name"),
            "email": token_data.get("email"),
            "scopes": token_data.get("scope", "").split(),
            "is_obo": token_data.get("token_type") == "obo",
            "delegation_chain": token_data.get("delegation_chain", [])
        }
        
        log(self.gateway_name, f"  ✓ Request authorized")
        return True, request, None
    
    def process_obo_request(self, request: GatewayRequest, 
                            step: Optional[int] = None) -> tuple:
        """Process request with OBO token (cross-namespace)."""
        log(self.gateway_name, f"Processing OBO token request", step=step)
        
        # Extract OBO token
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return False, None, "Missing Authorization header"
        
        token_jwt = auth_header.replace("Bearer ", "")
        token_data = self.external_iam.validate_token(token_jwt)
        
        if not token_data:
            return False, None, "Invalid OBO token"
        
        # Verify it's an OBO token
        if token_data.get("token_type") != "obo":
            log(self.gateway_name, f"  ⚠️ Warning: Expected OBO token, got regular token")
        
        # Verify audience
        audiences = token_data.get("aud", [])
        if self.client_id not in audiences and self.gateway_name not in audiences:
            return False, None, f"Invalid audience for {self.gateway_name}"
        
        # Log delegation chain
        delegation_chain = token_data.get("delegation_chain", [])
        log(self.gateway_name, f"  ✓ OBO token validated")
        log(self.gateway_name, f"  Original subject: {token_data.get('name')} ({token_data.get('sub')})")
        log(self.gateway_name, f"  Delegation chain: {' → '.join(delegation_chain) if delegation_chain else 'direct'}")
        
        # Reconstruct user context
        request.user_context = {
            "user_id": token_data.get("sub"),
            "name": token_data.get("name"),
            "delegation_chain": delegation_chain,
            "is_obo": True
        }
        
        return True, request, None
    
    def run(self):
        while self.running:
            time.sleep(0.1)


# ============================================================================
# Application Services (with OBO support)
# ============================================================================

class WebApplication(threading.Thread):
    """Web Application - handles customer login."""
    
    def __init__(self, external_iam: ExternalIAM, kong_gateway: KongGateway):
        super().__init__(name="WebApp", daemon=True)
        self.external_iam = external_iam
        self.kong = kong_gateway
        self.sessions: Dict[str, Dict] = {}
        self.running = True
    
    def login(self, username: str, password: str) -> Optional[str]:
        """Handle customer login."""
        log("WebApp", f"Customer login initiated", step=1)
        
        requested_scopes = ["openid", "profile", "chatbot:access", "agent:invoke"]
        
        log("WebApp", "Requesting tokens from External IAM", step=2)
        log("Customer", f"Submitting credentials")
        
        tokens = self.external_iam.authenticate_direct(username, password, requested_scopes)
        
        if not tokens:
            log("WebApp", "❌ Authentication failed")
            return None
        
        access_token, id_token, refresh_token = tokens
        
        session_id = secrets.token_urlsafe(32)
        self.sessions[session_id] = {
            "access_token": access_token,
            "id_token": id_token,
            "refresh_token": refresh_token,
            "user": access_token.claims
        }
        
        log("WebApp", f"✓ Session established for: {access_token.claims.get('name')}", step=6)
        return session_id
    
    def create_api_request(self, session_id: str, path: str, 
                            action: Dict) -> Optional[GatewayRequest]:
        """Create API request to be sent through Kong Gateway."""
        session = self.sessions.get(session_id)
        if not session:
            return None
        
        access_token = session["access_token"]
        
        log("Customer", f"Triggering action: {action.get('action')}", step=7)
        log("WebApp", f"Creating API request to Kong Gateway", step=8)
        
        return GatewayRequest(
            request_id=str(uuid.uuid4()),
            method="POST",
            path=path,
            headers={
                "Authorization": f"Bearer {access_token.to_jwt_mock()}",
                "Content-Type": "application/json"
            },
            body=action
        )
    
    def run(self):
        while self.running:
            time.sleep(0.1)


class AgentServiceB(threading.Thread):
    """Agent Service B - requests OBO token before calling Agent A."""
    
    def __init__(self, token_exchange: TokenExchangeService):
        super().__init__(name="AgentB", daemon=True)
        self.token_exchange = token_exchange
        self.running = True
        self.service_id = "agent-service-b"
        self.service_secret = "agent-b-secret"
    
    def process_request(self, request: GatewayRequest, customer_token: str) -> tuple:
        """Process request and obtain OBO token if cross-namespace call needed."""
        log("AgentB", f"Received pre-validated request from Kong", step=12)
        log("AgentB", f"  User: {request.user_context.get('name') if request.user_context else 'N/A'}")
        log("AgentB", f"  Correlation ID: {request.headers.get('X-Correlation-ID')}")
        
        needs_namespace_a = request.body.get("requires_namespace_a", True)
        
        if needs_namespace_a:
            log("AgentB", "Request requires Agent Service A (Namespace A)", step=13)
            log("AgentB", "Need to obtain OBO token to act on behalf of customer")
            
            # THIS IS THE KEY DIFFERENCE: Agent B exchanges customer token for OBO token
            log("AgentB", "Requesting OBO token exchange...", step=14)
            
            obo_token = self.token_exchange.exchange_token(
                subject_token=customer_token,
                actor_id=self.service_id,
                actor_secret=self.service_secret,
                audience=["kong-gateway-a", "agent-service-a"],
                scopes=["agent:invoke"],
                step=15
            )
            
            if not obo_token:
                log("AgentB", "❌ Failed to obtain OBO token")
                return False, None
            
            log("AgentB", f"✓ OBO token obtained", step=16)
            log("AgentB", f"  Now acting as: {obo_token.get_actor_description()}")
            
            return True, {
                "needs_cross_namespace": True,
                "obo_token": obo_token,
                "payload": request.body,
                "correlation_id": request.headers.get("X-Correlation-ID")
            }
        
        return False, {"result": "Processed locally in Namespace B"}
    
    def receive_cross_namespace_response(self, response: ServiceResponse) -> ServiceResponse:
        """Handle response from cross-namespace call."""
        log("AgentB", "Received cross-namespace response", step=25)
        return response
    
    def run(self):
        while self.running:
            time.sleep(0.1)


class AgentServiceA(threading.Thread):
    """Agent Service A - validates OBO token and sees delegation chain."""
    
    def __init__(self, token_exchange: TokenExchangeService):
        super().__init__(name="AgentA", daemon=True)
        self.token_exchange = token_exchange
        self.running = True
        self.service_id = "agent-service-a"
        self.service_secret = "agent-a-secret"
    
    def process_request(self, request: GatewayRequest, obo_token: Token) -> Optional[ServiceRequest]:
        """Process request with OBO token - can see full delegation chain."""
        log("AgentA", "Processing request from Kong Gateway A", step=20)
        
        # The OBO token tells us exactly who is acting on behalf of whom
        log("AgentA", "Analyzing OBO token delegation chain:")
        log("AgentA", f"  Original subject: {obo_token.subject}")
        if obo_token.actor_chain:
            log("AgentA", f"  Full chain: {obo_token.get_actor_description()}")
            for i, actor in enumerate(obo_token.actor_chain.actors):
                log("AgentA", f"    [{i+1}] {actor['actor_name']} ({actor['actor_type']})")
        
        user_context = request.user_context or {}
        
        # For this demo, Agent A could also exchange for its own OBO token
        # to call further downstream services
        log("AgentA", "Need to call Internal Service A2", step=21)
        
        # Create internal request with OBO context
        internal_request = ServiceRequest(
            request_id=request.request_id,
            payload={
                **request.body,
                "processed_by": "agent-a",
                "obo_chain": obo_token.get_actor_description(),
                "original_user": obo_token.subject
            },
            user_context=user_context,
            obo_token=obo_token,
            source_service="agent-service-a",
            target_service="internal-service-a2",
            correlation_id=request.headers.get("X-Correlation-ID")
        )
        
        return internal_request
    
    def receive_response(self, response: ServiceResponse) -> ServiceResponse:
        log("AgentA", "Received response from Service A2", step=23)
        return response
    
    def run(self):
        while self.running:
            time.sleep(0.1)


class InternalServiceA2(threading.Thread):
    """Internal Service A2 - can see full OBO chain for audit."""
    
    def __init__(self):
        super().__init__(name="ServiceA2", daemon=True)
        self.running = True
    
    def process_request(self, request: ServiceRequest) -> ServiceResponse:
        """Process business logic with full audit trail from OBO token."""
        log("ServiceA2", "Received request (intra-namespace)")
        log("ServiceA2", f"  Request from: {request.source_service}")
        log("ServiceA2", f"  Correlation ID: {request.correlation_id}")
        
        # The OBO token provides complete audit trail
        if request.obo_token:
            log("ServiceA2", f"  ★ OBO Audit Trail: {request.obo_token.get_actor_description()}")
            log("ServiceA2", f"  ★ Original user: {request.obo_token.subject}")
        
        log("ServiceA2", "Processing business logic...", step=22)
        time.sleep(0.3)
        
        obo_chain = request.payload.get('obo_chain', 'N/A')
        
        result = {
            "status": "completed",
            "message": f"Successfully processed: {request.payload.get('action')}",
            "data": {
                "request_id": request.request_id,
                "processed_at": datetime.now().isoformat(),
                "result": "The answer to your question is 42."
            },
            "audit": {
                "processed_by": "internal-service-a2",
                "original_user_id": request.payload.get("original_user"),
                "obo_delegation_chain": obo_chain,
                "action": request.payload.get("action"),
                "correlation_id": request.correlation_id
            }
        }
        
        log("ServiceA2", "✓ Processing complete")
        return ServiceResponse(request_id=request.request_id, success=True, data=result)
    
    def run(self):
        while self.running:
            time.sleep(0.1)


# ============================================================================
# Demo Orchestrator
# ============================================================================

def run_demo():
    """Run the OBO authentication flow demo."""
    
    print("\n" + "="*80)
    print(" On-Behalf-Of (OBO) Authentication Flow Demo (RFC 8693)")
    print("="*80 + "\n")
    
    # Initialize services
    print("Initializing services...\n")
    
    external_iam = ExternalIAM()
    internal_iam = InternalIAM()
    token_exchange = TokenExchangeService(external_iam)
    
    kong_a = KongGateway(
        name="KongA", namespace="namespace-a",
        external_iam=external_iam, token_exchange=token_exchange,
        client_id="kong-gateway-a", client_secret="kong-a-secret"
    )
    
    kong_b = KongGateway(
        name="KongB", namespace="namespace-b",
        external_iam=external_iam, token_exchange=token_exchange,
        client_id="kong-gateway-b", client_secret="kong-b-secret"
    )
    
    web_app = WebApplication(external_iam, kong_a)
    agent_b = AgentServiceB(token_exchange)
    agent_a = AgentServiceA(token_exchange)
    service_a2 = InternalServiceA2()
    
    services = [external_iam, internal_iam, token_exchange, kong_a, kong_b, 
                web_app, agent_b, agent_a, service_a2]
    for service in services:
        service.start()
    
    time.sleep(0.5)
    
    print("-"*80)
    print(" PHASE 1: Customer Authentication (with may_act claim)")
    print("-"*80 + "\n")
    
    session_id = web_app.login(
        username="customer@example.com",
        password="SecurePass123!"
    )
    
    if not session_id:
        print("\n❌ Login failed!")
        return
    
    print("\n" + "-"*80)
    print(" PHASE 2: Request Through Kong Gateway B")
    print("-"*80 + "\n")
    
    time.sleep(0.5)
    
    chatbot_action = {
        "action": "ask_question",
        "query": "What is the meaning of life?",
        "requires_namespace_a": True
    }
    
    gateway_request = web_app.create_api_request(
        session_id, "/api/v1/chatbot/query", chatbot_action
    )
    
    if not gateway_request:
        print("\n❌ Failed to create request!")
        return
    
    # Store customer token for OBO exchange
    customer_token = gateway_request.headers["Authorization"].replace("Bearer ", "")
    
    time.sleep(0.3)
    
    log("WebApp", "Sending request to Kong Gateway B", step=9)
    success, processed_request, error = kong_b.process_ingress(
        gateway_request, required_scopes=["chatbot:access"], step=10
    )
    
    if not success:
        print(f"\n❌ Kong Gateway B rejected request: {error}")
        return
    
    time.sleep(0.3)
    log("KongB", "Routing to Agent Service B", step=11)
    
    # Agent B processes and requests OBO token
    needs_cross_ns, agent_b_result = agent_b.process_request(processed_request, customer_token)
    
    if needs_cross_ns:
        print("\n" + "-"*80)
        print(" PHASE 3: Cross-Namespace Call WITH OBO Token")
        print("-"*80 + "\n")
        
        obo_token = agent_b_result["obo_token"]
        
        time.sleep(0.3)
        
        # Create cross-namespace request WITH OBO token
        cross_ns_request = GatewayRequest(
            request_id=processed_request.request_id,
            method="POST",
            path="/api/v1/agents/process",
            headers={
                "Authorization": f"Bearer {obo_token.to_jwt_mock()}",
                "X-Correlation-ID": agent_b_result["correlation_id"] or "",
                "Content-Type": "application/json"
            },
            body=agent_b_result["payload"]
        )
        
        log("AgentB", "Sending request to Kong A with OBO token", step=17)
        
        # Kong A validates OBO token
        success, validated_request, error = kong_a.process_obo_request(
            cross_ns_request, step=18
        )
        
        if not success:
            print(f"\n❌ Kong Gateway A rejected request: {error}")
            return
        
        time.sleep(0.3)
        log("KongA", "Routing to Agent Service A", step=19)
        
        print("\n" + "-"*80)
        print(" PHASE 4: Agent A Processes with OBO Context")
        print("-"*80 + "\n")
        
        request_to_a2 = agent_a.process_request(validated_request, obo_token)
        
        if not request_to_a2:
            print("\n❌ Agent A processing failed!")
            return
        
        time.sleep(0.3)
        
        response_from_a2 = service_a2.process_request(request_to_a2)
        
        print("\n" + "-"*80)
        print(" PHASE 5: Response Propagation")
        print("-"*80 + "\n")
        
        response_at_a = agent_a.receive_response(response_from_a2)
        log("KongA", "Returning response to Agent B", step=24)
        response_at_b = agent_b.receive_cross_namespace_response(response_at_a)
        log("KongB", "Returning response to WebApp", step=26)
        log("WebApp", "Displaying result to customer", step=27)
    else:
        # Local processing (no cross-namespace needed)
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
    print(" On-Behalf-Of (OBO) Flow Summary")
    print("="*80)
    print("""
    ┌─────────────────────────────────────────────────────────────────────────────┐
    │  KEY DIFFERENCE: OBO Token Exchange (RFC 8693)                              │
    ├─────────────────────────────────────────────────────────────────────────────┤
    │                                                                             │
    │  Previous demos (demo.py, demo_kong.py):                                    │
    │  ─────────────────────────────────────────                                  │
    │  • Services just passed user context in headers                             │
    │  • No cryptographic proof of delegation                                     │
    │  • Services used their OWN identity for cross-namespace calls               │
    │                                                                             │
    │  This demo (demo_obo.py):                                                   │
    │  ────────────────────────                                                   │
    │  • Services EXCHANGE customer token for OBO token                           │
    │  • OBO token proves: "Agent B acting on behalf of Alice"                    │
    │  • Delegation chain recorded in token: Alice → Agent B                      │
    │  • Downstream services can verify the full chain                            │
    │                                                                             │
    └─────────────────────────────────────────────────────────────────────────────┘
    
    ┌─────────────────────────────────────────────────────────────────────────────┐
    │  Token Flow Comparison                                                      │
    ├─────────────────────────────────────────────────────────────────────────────┤
    │                                                                             │
    │  demo_kong.py:                                                              │
    │  ┌──────────┐    ┌──────────┐    ┌──────────┐                               │
    │  │ Customer │───→│  Kong B  │───→│  Kong A  │                               │
    │  │   JWT    │    │ Service  │    │ Service  │                               │
    │  └──────────┘    │  Token   │    │  Token   │                               │
    │                  └──────────┘    └──────────┘                               │
    │  Headers: X-Original-Consumer: user-12345 (just a string!)                  │
    │                                                                             │
    │  demo_obo.py:                                                               │
    │  ┌──────────┐    ┌──────────────────────────┐    ┌────────────────────────┐ │
    │  │ Customer │───→│      OBO Token           │───→│      OBO Token         │ │
    │  │   JWT    │    │ sub: user-12345          │    │ sub: user-12345        │ │
    │  │          │    │ act: { sub: agent-b }    │    │ act: { sub: agent-a,   │ │
    │  │          │    │                          │    │       act: agent-b }   │ │
    │  └──────────┘    └──────────────────────────┘    └────────────────────────┘ │
    │  The token ITSELF proves delegation (cryptographically signed!)             │
    │                                                                             │
    └─────────────────────────────────────────────────────────────────────────────┘
    
    ┌─────────────────────────────────────────────────────────────────────────────┐
    │  OBO Token Claims (RFC 8693)                                                │
    ├─────────────────────────────────────────────────────────────────────────────┤
    │                                                                             │
    │  {                                                                          │
    │    "sub": "user-12345",           // Original user (Alice)                  │
    │    "name": "Alice Customer",                                                │
    │    "act": {                       // Actor claim (who is acting)            │
    │      "sub": "agent-service-b",                                              │
    │      "act_type": "service"                                                  │
    │    },                                                                        │
    │    "delegation_chain": ["Agent Service B"],                                 │
    │    "token_type": "obo",                                                     │
    │    "scope": "agent:invoke",       // Scopes can be reduced                  │
    │    "aud": ["kong-gateway-a"]      // Specific audience                      │
    │  }                                                                          │
    │                                                                             │
    └─────────────────────────────────────────────────────────────────────────────┘
    
    ┌─────────────────────────────────────────────────────────────────────────────┐
    │  Security Benefits of OBO                                                   │
    ├─────────────────────────────────────────────────────────────────────────────┤
    │  ✓ Cryptographic proof of delegation (not just header strings)              │
    │  ✓ Delegation chain is tamper-proof (signed by token exchange service)     │
    │  ✓ Can limit delegation depth (prevent infinite chains)                     │
    │  ✓ Scopes can be narrowed at each hop                                       │
    │  ✓ may_act claim controls who can act on behalf of user                     │
    │  ✓ Full audit trail in the token itself                                     │
    └─────────────────────────────────────────────────────────────────────────────┘
    """)
    
    # Cleanup
    for service in services:
        service.running = False


if __name__ == "__main__":
    run_demo()
