"""
Registry Service - FastAPI application
Handles user authentication and management of software stacks to monitor.

Author: Sai Siddarth Sandur Kiran Kumar
Student ID: A00336127
MSc Software Design with Cloud Native Computing - TUS Athlone
"""

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from typing import Optional
import boto3
import uuid
import os
import hashlib
from datetime import datetime
from jose import jwt, JWTError
from boto3.dynamodb.conditions import Key

app = FastAPI(
    title="Registry Service",
    description="Manages user accounts and registered software stacks",
    version="1.0.0"
)

security = HTTPBearer()

# Initialise AWS clients using IRSA — no hardcoded credentials needed.
# When running inside EKS, IRSA injects credentials automatically
# via the service account annotation. Locally, AWS CLI credentials are used.
dynamodb     = boto3.resource("dynamodb", region_name=os.environ["AWS_REGION"])
stacks_table = dynamodb.Table(os.environ["STACKS_TABLE"])
users_table  = dynamodb.Table(os.environ["USERS_TABLE"])

# JWT secret is pulled from environment variable.
# In production this is injected by External Secrets Operator
# which syncs from AWS Secrets Manager into a Kubernetes secret.
JWT_SECRET = os.environ["JWT_SECRET"]


# ── Pydantic models ──────────────────────────────────────────

class StackItem(BaseModel):
    """Represents a software package the user wants to monitor for CVEs."""
    package:     str            # e.g. "django"
    version:     str            # e.g. "4.2.0"
    ecosystem:   str            # e.g. "PyPI", "npm", "Maven"
    description: Optional[str] = None

class LoginRequest(BaseModel):
    username: str
    password: str

class RegisterRequest(BaseModel):
    username: str
    password: str


# ── Helper functions ─────────────────────────────────────────

def hash_password(password: str) -> str:
    """
    SHA-256 password hashing.
    Note: In a production system bcrypt would be more appropriate,
    but SHA-256 is sufficient for this research prototype.
    """
    return hashlib.sha256(password.encode()).hexdigest()


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> str:
    """Validate JWT token and return the username."""
    try:
        payload = jwt.decode(
            credentials.credentials,
            JWT_SECRET,
            algorithms=["HS256"]
        )
        return payload["sub"]
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token. Please login again."
        )


# ── Routes ───────────────────────────────────────────────────

@app.get("/health")
def health_check():
    """Health check endpoint used by Kubernetes liveness probe."""
    return {"status": "healthy", "service": "registry"}


@app.post("/auth/register", status_code=201)
def register_user(req: RegisterRequest):
    """Register a new user account."""
    existing = users_table.get_item(Key={"username": req.username})
    if existing.get("Item"):
        raise HTTPException(
            status_code=400,
            detail="Username already exists"
        )
    users_table.put_item(Item={
        "username":      req.username,
        "password_hash": hash_password(req.password),
        "created_at":    datetime.utcnow().isoformat()
    })
    return {"message": "User registered successfully"}


@app.post("/auth/login")
def login(req: LoginRequest):
    """Authenticate user and return a JWT token."""
    response = users_table.get_item(Key={"username": req.username})
    user     = response.get("Item")

    if not user or user["password_hash"] != hash_password(req.password):
        raise HTTPException(
            status_code=401,
            detail="Invalid username or password"
        )

    # Create JWT token.
    # Note: this prototype does not implement token expiry for simplicity.
    # A production system would include an expiry claim.
    token = jwt.encode(
        {"sub": req.username},
        JWT_SECRET,
        algorithm="HS256"
    )
    return {"access_token": token, "token_type": "bearer"}


@app.post("/stacks", status_code=201)
def create_stack(
    item: StackItem,
    user: str = Depends(get_current_user)
):
    """Register a new software package to monitor for CVEs."""
    stack_id = str(uuid.uuid4())

    stacks_table.put_item(Item={
        "user_id":     user,
        "stack_id":    stack_id,
        "package":     item.package,
        "version":     item.version,
        "ecosystem":   item.ecosystem,
        "description": item.description or "",
        "created_at":  datetime.utcnow().isoformat(),
    })

    return {
        "stack_id": stack_id,
        "message":  f"Now monitoring {item.package}=={item.version} for CVEs"
    }


@app.get("/stacks")
def list_stacks(user: str = Depends(get_current_user)):
    """Return all stacks registered by the current user."""
    response = stacks_table.query(
        KeyConditionExpression=Key("user_id").eq(user)
    )
    return {"stacks": response.get("Items", [])}


@app.get("/stacks/{stack_id}")
def get_stack(
    stack_id: str,
    user: str = Depends(get_current_user)
):
    """Return a single stack by ID."""
    response = stacks_table.get_item(
        Key={"user_id": user, "stack_id": stack_id}
    )
    item = response.get("Item")

    if not item:
        raise HTTPException(status_code=404, detail="Stack not found")

    return item


@app.delete("/stacks/{stack_id}", status_code=204)
def delete_stack(
    stack_id: str,
    user: str = Depends(get_current_user)
):
    """Remove a stack from monitoring."""
    stacks_table.delete_item(
        Key={"user_id": user, "stack_id": stack_id}
    )