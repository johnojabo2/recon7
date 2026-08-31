import uuid
from typing import Optional
from pydantic import BaseModel, Field


class TenantContext(BaseModel):
    """Execution context carrying tenant and optional user identification."""
    tenant_id: str = Field(..., description="UUID or unique identifier for the tenant")
    user_id: Optional[str] = Field(None, description="Optional user ID within the tenant")


def generate_tenant_id() -> str:
    """Generate a clean UUID string for tenant ID."""
    return str(uuid.uuid4())


def validate_tenant_id(tenant_id: str) -> bool:
    """Validate tenant ID format."""
    if not tenant_id or not isinstance(tenant_id, str):
        return False
    return len(tenant_id.strip()) > 0
