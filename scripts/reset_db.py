import os
import sys

# Add project root to sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.config import settings
from core.auth import hash_password, verify_password, create_access_token
from storage.models import Base, Tenant, User, AuthorizedScope
from storage.db import engine, SessionLocal, init_db

def wipe_and_reset_db():
    print("==================================================")
    print("           RECON7 DATABASE WIPE & RESET          ")
    print("==================================================")
    
    # 1. Close connections and drop all tables
    print("[1/4] Dropping all existing database tables...")
    Base.metadata.drop_all(bind=engine)
    
    # 2. Re-create all tables via init_db
    print("[2/4] Initializing fresh schema and tables...")
    init_db()
    
    # 3. Explicitly verify single clean default tenant and admin user
    print("[3/4] Provisioning clean single default tenant and admin...")
    with SessionLocal() as db:
        tenant = db.query(Tenant).filter(Tenant.id == "default-tenant").first()
        if not tenant:
            tenant = Tenant(id="default-tenant", name="Default Organization")
            db.add(tenant)
            db.commit()
            db.refresh(tenant)

        # Default Admin User
        admin_email = "admin@recon7.io"
        admin_pass = "Admin@12345"
        admin_user = db.query(User).filter(User.email == admin_email).first()
        if not admin_user:
            admin_user = User(
                email=admin_email,
                password_hash=hash_password(admin_pass),
                tenant_id=tenant.id,
                full_name="Primary Administrator",
                role="admin",
                is_active=True,
            )
            db.add(admin_user)
            db.commit()
            db.refresh(admin_user)
            
        print(f"      [+] Tenant Created: '{tenant.name}' (ID: {tenant.id})")
        print(f"      [+] Admin Created:  '{admin_user.email}' (Password: {admin_pass})")
        
        # Test Password Verification
        is_valid = verify_password(admin_pass, admin_user.password_hash)
        print(f"      [+] Credential verification test: {'PASSED' if is_valid else 'FAILED'}")
        
        # Generate Test Token
        token = create_access_token(user_id=admin_user.id, tenant_id=tenant.id, email=admin_user.email, role=admin_user.role)
        print(f"      [+] Sample Bearer Token: {token[:30]}...")

    print("[4/4] Database reset complete! Ready for end-to-end testing.")
    print("==================================================")

if __name__ == "__main__":
    wipe_and_reset_db()
