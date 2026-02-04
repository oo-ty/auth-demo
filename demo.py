#!/usr/bin/env python3
"""
Cross-Namespace Authentication & Authorization Demo (2026 Standards)

This demo simulates the complete authentication flow:
1. Customer login via External IAM (OIDC)
2. Customer triggers API call to Agent Service B (Namespace B)
3. Agent B authenticates with Internal IAM for cross-namespace call
4. Agent A (Namespace A) processes request, calls internal service
5. Results propagate back through the stack

Run: python demo.py
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
        'Customer': '\033[96m',      # Cyan
        'WebApp': '\033[94m',        # Blue
        'ExternalIAM': '\033[95m',   # Magenta
        'InternalIAM': '\033[93m',   # Yellow
        'AgentB': '\033[92m',        # Green
        'AgentA': '\033[91m',        # Red
        'ServiceA2': '\033[97m',     # White
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
logger = logging.getLogger('auth_demo')
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
class ServiceRequest:
    """Request passed between services."""
    request_id: str
    payload: Dict[str, Any]
    user_context: Optional[Dict[str, Any]] = None  # Propagated user info
    service_token: Optional[str] = None  # For cross-namespace
    customer_token: Optional[str] = None  # Original customer token
    source_service: Optional[str] = None
    target_service: Optional[str] = None


@dataclass
class ServiceResponse:
    """Response from services."""
    request_id: str
    success: bool
    data: Dict[str, Any]
    error: Optional[str] = None


# ============================================================================
# Mock IAM Services
# ============================================================================

class ExternalIAM(threading.Thread):
    """
    External IAM Service (OIDC Provider for customer authentication).
    Handles OAuth 2.1 with PKCE flow.
    """
    
    def __init__(self):
        super().__init__(name="ExternalIAM", daemon=True)
        self.request_queue = queue.Queue()
        self.users_db = {
            "customer@example.com": {
                "password_hash": hashlib.sha256("SecurePass123!".encode()).hexdigest(),
                "user_id": "user-12345",
                "name": "Alice Customer",
                "allowed_scopes": ["openid", "profile", "chatbot:access", "agent:invoke"]
            }
        }
        self.auth_codes = {}  # code -> (user_id, code_verifier_hash, scopes)
        self.running = True
    
    def authenticate(self, username: str, password: str, code_challenge: str, 
                     requested_scopes: List[str]) -> Optional[str]:
        """Authenticate user and return authorization code (PKCE flow)."""
        log("ExternalIAM", f"Authenticating user: {username}", step=4)
        
        user = self.users_db.get(username)
        if not user:
            log("ExternalIAM", "❌ User not found")
            return None
            
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        if password_hash != user["password_hash"]:
            log("ExternalIAM", "❌ Invalid password")
            return None
        
        # Filter to allowed scopes
        granted_scopes = [s for s in requested_scopes if s in user["allowed_scopes"]]
        
        # Generate authorization code
        auth_code = secrets.token_urlsafe(32)
        self.auth_codes[auth_code] = {
            "user_id": user["user_id"],
            "username": username,
            "name": user["name"],
            "code_challenge": code_challenge,
            "scopes": granted_scopes,
            "expires": datetime.now() + timedelta(minutes=5)
        }
        
        log("ExternalIAM", f"✓ User authenticated, auth code issued", step=5)
        return auth_code
    
    def exchange_code(self, auth_code: str, code_verifier: str) -> Optional[tuple]:
        """Exchange auth code for tokens (PKCE validation)."""
        log("ExternalIAM", "Validating authorization code exchange", step=7)
        
        code_data = self.auth_codes.get(auth_code)
        if not code_data or datetime.now() > code_data["expires"]:
            log("ExternalIAM", "❌ Invalid or expired auth code")
            return None
        
        # Verify PKCE code_verifier
        verifier_hash = base64.urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode()).digest()
        ).decode().rstrip('=')
        
        if verifier_hash != code_data["code_challenge"]:
            log("ExternalIAM", "❌ PKCE verification failed")
            return None
        
        # Issue tokens
        now = datetime.now()
        
        access_token = Token(
            token_id=str(uuid.uuid4()),
            issuer="https://external-iam.example.com",
            subject=code_data["user_id"],
            audience=["webapp", "agent-service-b"],
            scopes=code_data["scopes"],
            expires_at=now + timedelta(minutes=30),
            claims={"name": code_data["name"], "email": code_data["username"]}
        )
        
        id_token = Token(
            token_id=str(uuid.uuid4()),
            issuer="https://external-iam.example.com",
            subject=code_data["user_id"],
            audience=["webapp"],
            scopes=["openid", "profile"],
            expires_at=now + timedelta(minutes=30),
            claims={"name": code_data["name"], "email": code_data["username"]}
        )
        
        # Invalidate auth code (one-time use)
        del self.auth_codes[auth_code]
        
        log("ExternalIAM", f"✓ Tokens issued - scopes: {access_token.scopes}", step=8)
        return access_token, id_token
    
    def validate_token(self, token_jwt: str) -> Optional[Dict]:
        """Validate and decode a token (mock JWT validation)."""
        try:
            # Extract payload from mock JWT
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
    Handles OAuth 2.0 Client Credentials with workload identity (SPIFFE-like).
    """
    
    def __init__(self):
        super().__init__(name="InternalIAM", daemon=True)
        self.running = True
        # Registered services with their allowed targets
        self.service_registry = {
            "agent-service-b": {
                "spiffe_id": "spiffe://cluster.local/ns/namespace-b/sa/agent-b",
                "allowed_audiences": ["agent-service-a", "data-service"],
                "allowed_scopes": ["cross-namespace:invoke", "data:read"]
            },
            "agent-service-a": {
                "spiffe_id": "spiffe://cluster.local/ns/namespace-a/sa/agent-a",
                "allowed_audiences": ["internal-service-a2", "db-service"],
                "allowed_scopes": ["internal:invoke", "db:read", "db:write"]
            }
        }
    
    def get_service_token(self, client_id: str, client_secret: str, 
                          audience: str, scopes: List[str]) -> Optional[Token]:
        """
        Issue service token via client_credentials grant.
        In production, this would validate mTLS cert / SPIFFE identity.
        """
        log("InternalIAM", f"Service token request from: {client_id}", step=15)
        log("InternalIAM", f"  Target audience: {audience}")
        log("InternalIAM", f"  Requested scopes: {scopes}")
        
        service = self.service_registry.get(client_id)
        if not service:
            log("InternalIAM", f"❌ Unknown service: {client_id}")
            return None
        
        # Validate audience is allowed
        if audience not in service["allowed_audiences"]:
            log("InternalIAM", f"❌ Service not authorized for audience: {audience}")
            return None
        
        # Filter to allowed scopes
        granted_scopes = [s for s in scopes if s in service["allowed_scopes"]]
        if not granted_scopes:
            log("InternalIAM", "❌ No valid scopes granted")
            return None
        
        # Issue service token
        token = Token(
            token_id=str(uuid.uuid4()),
            issuer="https://internal-iam.cluster.local",
            subject=service["spiffe_id"],
            audience=[audience],
            scopes=granted_scopes,
            expires_at=datetime.now() + timedelta(minutes=10),
            claims={
                "client_id": client_id,
                "namespace": client_id.split("-")[-1] if "-" in client_id else "default"
            }
        )
        
        log("InternalIAM", f"✓ Service token issued for {client_id} -> {audience}", step=16)
        log("InternalIAM", f"  Granted scopes: {granted_scopes}")
        return token
    
    def run(self):
        while self.running:
            time.sleep(0.1)


# ============================================================================
# Application Services
# ============================================================================

class WebApplication(threading.Thread):
    """
    Web Application (Frontend + BFF) in Namespace A.
    Handles customer login and forwards requests to backend services.
    """
    
    def __init__(self, external_iam: ExternalIAM):
        super().__init__(name="WebApp", daemon=True)
        self.external_iam = external_iam
        self.request_queue = queue.Queue()
        self.response_queue = queue.Queue()
        self.sessions = {}  # session_id -> tokens
        self.running = True
    
    def login(self, username: str, password: str) -> Optional[str]:
        """Handle customer login with OIDC/PKCE flow."""
        log("WebApp", f"Customer login initiated", step=1)
        
        # Generate PKCE code verifier and challenge
        code_verifier = secrets.token_urlsafe(64)
        code_challenge = base64.urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode()).digest()
        ).decode().rstrip('=')
        
        requested_scopes = ["openid", "profile", "chatbot:access", "agent:invoke"]
        
        log("WebApp", "Redirecting to External IAM for authentication", step=2)
        
        # Step 3-5: User authenticates with External IAM
        log("Customer", f"Submitting credentials to External IAM", step=3)
        auth_code = self.external_iam.authenticate(
            username, password, code_challenge, requested_scopes
        )
        
        if not auth_code:
            log("WebApp", "❌ Authentication failed")
            return None
        
        log("Customer", "Received authorization code, returning to WebApp", step=6)
        
        # Exchange code for tokens
        tokens = self.external_iam.exchange_code(auth_code, code_verifier)
        if not tokens:
            log("WebApp", "❌ Token exchange failed")
            return None
        
        access_token, id_token = tokens
        
        # Create session
        session_id = secrets.token_urlsafe(32)
        self.sessions[session_id] = {
            "access_token": access_token,
            "id_token": id_token,
            "user": access_token.claims
        }
        
        log("WebApp", f"✓ Session established for: {access_token.claims.get('name')}", step=9)
        return session_id
    
    def handle_chatbot_action(self, session_id: str, action: Dict) -> Optional[ServiceRequest]:
        """Forward chatbot action to Agent Service B."""
        session = self.sessions.get(session_id)
        if not session:
            log("WebApp", "❌ Invalid session")
            return None
        
        access_token = session["access_token"]
        
        log("Customer", f"Triggering chatbot action: {action.get('action')}", step=10)
        
        # Validate scope for chatbot access
        log("WebApp", "Validating scope: chatbot:access", step=11)
        if not access_token.has_scope("chatbot:access"):
            log("WebApp", "❌ Access denied - missing chatbot:access scope")
            return None
        log("WebApp", "✓ Scope validated")
        
        # Create request with user context
        request = ServiceRequest(
            request_id=str(uuid.uuid4()),
            payload=action,
            customer_token=access_token.to_jwt_mock(),
            user_context={
                "user_id": access_token.subject,
                "name": access_token.claims.get("name"),
                "scopes": access_token.scopes
            },
            source_service="webapp",
            target_service="agent-service-b"
        )
        
        log("WebApp", f"Forwarding request to Agent Service B", step=12)
        return request
    
    def run(self):
        while self.running:
            time.sleep(0.1)


class AgentServiceB(threading.Thread):
    """
    Agent Service B in Namespace B.
    Receives customer requests, may need to call services in other namespaces.
    """
    
    def __init__(self, internal_iam: InternalIAM, external_iam: ExternalIAM):
        super().__init__(name="AgentB", daemon=True)
        self.internal_iam = internal_iam
        self.external_iam = external_iam
        self.running = True
        self.service_id = "agent-service-b"
        self.client_secret = "agent-b-secret-key"  # Would be from secure vault
    
    def process_request(self, request: ServiceRequest) -> Optional[ServiceRequest]:
        """Process incoming request and prepare cross-namespace call if needed."""
        
        # Validate customer token
        log("AgentB", "Validating customer access token")
        if not request.customer_token:
            log("AgentB", "❌ Missing customer token")
            return None
        token_data = self.external_iam.validate_token(request.customer_token)
        if not token_data:
            log("AgentB", "❌ Invalid customer token")
            return None
        
        # Check required scope
        scopes = token_data.get("scope", "").split()
        if "agent:invoke" not in scopes:
            log("AgentB", "❌ Missing required scope: agent:invoke")
            return None
        
        log("AgentB", f"✓ Customer token validated - user: {token_data.get('name')}")
        
        # Analyze request and determine routing
        log("AgentB", f"Analyzing request: {request.payload}", step=13)
        
        # Simulate logic that determines we need Agent A
        needs_agent_a = request.payload.get("requires_namespace_a", True)
        
        if needs_agent_a:
            log("AgentB", "Request requires Agent Service A in Namespace A")
            
            # Get service token for cross-namespace call
            log("AgentB", "Requesting service token from Internal IAM", step=14)
            
            service_token = self.internal_iam.get_service_token(
                client_id=self.service_id,
                client_secret=self.client_secret,
                audience="agent-service-a",
                scopes=["cross-namespace:invoke"]
            )
            
            if not service_token:
                log("AgentB", "❌ Failed to obtain service token")
                return None
            
            # Prepare cross-namespace request
            cross_ns_request = ServiceRequest(
                request_id=request.request_id,
                payload=request.payload,
                service_token=service_token.to_jwt_mock(),
                user_context=request.user_context,  # Propagate user context
                source_service=self.service_id,
                target_service="agent-service-a"
            )
            
            log("AgentB", f"Calling Agent Service A with service token", step=17)
            user_name = request.user_context.get('name') if request.user_context else 'unknown'
            log("AgentB", f"  User context preserved: {user_name}")
            
            return cross_ns_request
        
        return None
    
    def receive_response(self, response: ServiceResponse) -> ServiceResponse:
        """Process response from Agent A and return to caller."""
        log("AgentB", f"Received response from Agent A", step=21)
        log("AgentB", f"Forwarding response to WebApp", step=22)
        return response
    
    def run(self):
        while self.running:
            time.sleep(0.1)


class AgentServiceA(threading.Thread):
    """
    Agent Service A in Namespace A.
    Processes requests from other namespaces, may call internal services.
    """
    
    def __init__(self, internal_iam: InternalIAM):
        super().__init__(name="AgentA", daemon=True)
        self.internal_iam = internal_iam
        self.running = True
        self.service_id = "agent-service-a"
    
    def process_request(self, request: ServiceRequest) -> Optional[ServiceRequest]:
        """Process incoming cross-namespace request."""
        
        # Validate service token
        log("AgentA", "Validating incoming service token")
        
        if not request.service_token:
            log("AgentA", "❌ Missing service token")
            return None
        
        try:
            parts = request.service_token.split('.')
            token_data = json.loads(base64.b64decode(parts[1] + '=='))
        except:
            log("AgentA", "❌ Invalid service token format")
            return None
        
        # Verify audience
        audiences = token_data.get("aud", [])
        if "agent-service-a" not in audiences:
            log("AgentA", f"❌ Invalid audience: {audiences}")
            return None
        
        # Verify scope
        scopes = token_data.get("scope", "").split()
        if "cross-namespace:invoke" not in scopes:
            log("AgentA", "❌ Missing required scope: cross-namespace:invoke")
            return None
        
        log("AgentA", f"✓ Service token validated")
        log("AgentA", f"  Source: {token_data.get('client_id')}")
        user_name = request.user_context.get('name') if request.user_context else 'unknown'
        log("AgentA", f"  User context: {user_name} (for audit)")
        
        # Determine if internal service call is needed
        log("AgentA", "Processing request, need to call Internal Service A2", step=18)
        
        # Create internal request (no additional auth needed - same namespace)
        internal_request = ServiceRequest(
            request_id=request.request_id,
            payload={
                **request.payload,
                "processed_by": "agent-a",
                "user_context": request.user_context  # For audit trail
            },
            source_service="agent-service-a",
            target_service="internal-service-a2"
            # No service_token needed - same namespace, mTLS via service mesh
        )
        
        return internal_request
    
    def receive_response(self, response: ServiceResponse) -> ServiceResponse:
        """Process response from internal service."""
        log("AgentA", f"Received response from Service A2", step=20)
        return response
    
    def run(self):
        while self.running:
            time.sleep(0.1)


class InternalServiceA2(threading.Thread):
    """
    Internal Service A2 in Namespace A.
    Performs actual business logic, trusts calls from same namespace (mTLS).
    """
    
    def __init__(self):
        super().__init__(name="ServiceA2", daemon=True)
        self.running = True
    
    def process_request(self, request: ServiceRequest) -> ServiceResponse:
        """Process the actual business logic."""
        log("ServiceA2", "Received request (same namespace - implicit trust via mTLS)")
        log("ServiceA2", f"  Request from: {request.source_service}")
        log("ServiceA2", f"  User context: {request.payload.get('user_context', {}).get('name')}")
        
        log("ServiceA2", "Processing business logic...", step=19)
        
        # Simulate some processing
        time.sleep(0.3)
        
        result = {
            "status": "completed",
            "message": f"Successfully processed request for {request.payload.get('action')}",
            "data": {
                "request_id": request.request_id,
                "processed_at": datetime.now().isoformat(),
                "result": "The answer to your question is 42."
            },
            "audit": {
                "processed_by": "internal-service-a2",
                "user_id": request.payload.get("user_context", {}).get("user_id"),
                "action": request.payload.get("action")
            }
        }
        
        log("ServiceA2", f"✓ Processing complete")
        
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
    """Run the complete authentication flow demo."""
    
    print("\n" + "="*80)
    print(" Cross-Namespace Authentication & Authorization Demo (2026 Standards)")
    print("="*80 + "\n")
    
    # Initialize all services
    print("Initializing services...\n")
    
    external_iam = ExternalIAM()
    internal_iam = InternalIAM()
    
    web_app = WebApplication(external_iam)
    agent_b = AgentServiceB(internal_iam, external_iam)
    agent_a = AgentServiceA(internal_iam)
    service_a2 = InternalServiceA2()
    
    # Start all services
    services = [external_iam, internal_iam, web_app, agent_b, agent_a, service_a2]
    for service in services:
        service.start()
    
    time.sleep(0.5)  # Let services initialize
    
    print("-"*80)
    print(" PHASE 1: Customer Authentication (OIDC + PKCE)")
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
    print(" PHASE 2-5: Cross-Namespace Service Invocation")
    print("-"*80 + "\n")
    
    time.sleep(0.5)
    
    # Customer triggers chatbot action
    chatbot_action = {
        "action": "ask_question",
        "query": "What is the meaning of life?",
        "requires_namespace_a": True
    }
    
    # WebApp forwards to Agent B
    request_to_b = web_app.handle_chatbot_action(session_id, chatbot_action)
    
    if not request_to_b:
        print("\n❌ Request handling failed at WebApp!")
        return
    
    time.sleep(0.3)
    
    # Agent B processes and calls Agent A
    request_to_a = agent_b.process_request(request_to_b)
    
    if not request_to_a:
        print("\n❌ Request handling failed at Agent B!")
        return
    
    time.sleep(0.3)
    
    # Agent A processes and calls internal service
    request_to_a2 = agent_a.process_request(request_to_a)
    
    if not request_to_a2:
        print("\n❌ Request handling failed at Agent A!")
        return
    
    time.sleep(0.3)
    
    # Internal Service A2 processes
    response_from_a2 = service_a2.process_request(request_to_a2)
    
    # Propagate responses back
    response_at_a = agent_a.receive_response(response_from_a2)
    response_at_b = agent_b.receive_response(response_at_a)
    
    log("WebApp", f"Displaying result to customer", step=23)
    
    print("\n" + "-"*80)
    print(" DEMO COMPLETE - Final Result")
    print("-"*80)
    print(f"\n✅ Success: {response_at_b.success}")
    print(f"📋 Result: {json.dumps(response_at_b.data, indent=2)}")
    
    print("\n" + "="*80)
    print(" Authentication Flow Summary")
    print("="*80)
    print("""
    ┌─────────────────────────────────────────────────────────────────────────┐
    │  1. Customer authenticated via OIDC/PKCE with External IAM              │
    │  2. WebApp validated customer's 'chatbot:access' scope                  │
    │  3. Agent B validated customer token and 'agent:invoke' scope           │
    │  4. Agent B obtained service token from Internal IAM                    │
    │  5. Agent A validated service token (audience + scope)                  │
    │  6. Service A2 trusted Agent A via same-namespace mTLS                  │
    │  7. User context propagated throughout for audit trail                  │
    └─────────────────────────────────────────────────────────────────────────┘
    """)
    
    # Cleanup
    for service in services:
        service.running = False


if __name__ == "__main__":
    run_demo()
