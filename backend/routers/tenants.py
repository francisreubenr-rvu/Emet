from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from db.database import get_db
from db.models import TenantModel, UserModel
from services.auth_guard import verify_global_admin

router = APIRouter(prefix="/api/tenants", tags=["tenants"])

@router.post("/")
def create_tenant(request: Request, data: dict, db: Session = Depends(get_db)):
    verify_global_admin(request)
    name = data.get("name")
    if not name:
        raise HTTPException(status_code=400, detail="Tenant name required")
    
    existing = db.query(TenantModel).filter(TenantModel.name == name).first()
    if existing:
        raise HTTPException(status_code=400, detail="Tenant already exists")
        
    tenant = TenantModel(name=name)
    db.add(tenant)
    db.commit()
    db.refresh(tenant)
    return {"id": tenant.id, "name": tenant.name}

@router.get("/")
def list_tenants(request: Request, db: Session = Depends(get_db)):
    verify_global_admin(request)
    tenants = db.query(TenantModel).all()
    return [{"id": t.id, "name": t.name} for t in tenants]

@router.post("/{tenant_id}/users")
def assign_user_to_tenant(tenant_id: int, request: Request, data: dict, db: Session = Depends(get_db)):
    verify_global_admin(request)
    email = data.get("email")
    role = data.get("role", "tenant_viewer")
    
    tenant = db.query(TenantModel).filter(TenantModel.id == tenant_id).first()
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")
        
    user = db.query(UserModel).filter(UserModel.email == email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
        
    user.tenant_id = tenant.id
    user.role = role
    db.commit()
    
    return {"message": f"User {email} assigned to tenant {tenant.name} as {role}"}