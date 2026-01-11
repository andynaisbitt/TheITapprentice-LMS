# Backend\app\api\v1\endpoints\admin\users.py
"""
Admin User Management Endpoints
Allows admins to view, edit, enable/disable user accounts
"""
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from sqlalchemy import or_, func
from typing import List, Optional
from datetime import datetime
import math

from app.core.database import get_db
from app.auth.dependencies import get_current_user, require_admin
from app.users.models import User, UserRole, SubscriptionStatus
from app.users.schemas import UserResponse, UserAdminUpdate, UserAdminCreate, UserListResponse
from app.core.security import get_password_hash
import secrets
import string

router = APIRouter(prefix="/admin/users", tags=["Admin - Users"])


@router.get("", response_model=UserListResponse)
async def get_all_users(
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(20, ge=1, le=100, description="Items per page"),
    search: Optional[str] = Query(None, description="Search by email, username, or name"),
    role: Optional[UserRole] = Query(None, description="Filter by role"),
    is_active: Optional[bool] = Query(None, description="Filter by active status"),
    is_verified: Optional[bool] = Query(None, description="Filter by verified status"),
    sort_by: str = Query("created_at", description="Sort field"),
    sort_order: str = Query("desc", description="Sort order (asc/desc)"),
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """
    Get paginated list of all users with filtering and search
    Requires ADMIN role
    """

    # Base query
    query = db.query(User)

    # Search filter
    if search:
        search_term = f"%{search}%"
        query = query.filter(
            or_(
                User.email.ilike(search_term),
                User.username.ilike(search_term),
                User.first_name.ilike(search_term),
                User.last_name.ilike(search_term)
            )
        )

    # Role filter
    if role:
        query = query.filter(User.role == role)

    # Active status filter
    if is_active is not None:
        query = query.filter(User.is_active == is_active)

    # Verified status filter
    if is_verified is not None:
        query = query.filter(User.is_verified == is_verified)

    # Get total count before pagination
    total = query.count()

    # Sorting
    sort_column = getattr(User, sort_by, User.created_at)
    if sort_order == "desc":
        query = query.order_by(sort_column.desc())
    else:
        query = query.order_by(sort_column.asc())

    # Pagination
    skip = (page - 1) * page_size
    users = query.offset(skip).limit(page_size).all()

    # Calculate pagination info
    total_pages = math.ceil(total / page_size) if total > 0 else 0

    return {
        "users": users,
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": total_pages
    }


@router.get("/stats", response_model=dict)
async def get_user_stats(
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """
    Get user statistics for dashboard
    Requires ADMIN role
    """

    # Total users
    total_users = db.query(func.count(User.id)).scalar()

    # Active users
    active_users = db.query(func.count(User.id)).filter(User.is_active == True).scalar()

    # Admin count
    admin_count = db.query(func.count(User.id)).filter(User.is_admin == True).scalar()

    # New users this month
    from datetime import datetime, timedelta
    thirty_days_ago = datetime.utcnow() - timedelta(days=30)
    new_this_month = db.query(func.count(User.id)).filter(User.created_at >= thirty_days_ago).scalar()

    # Users by role
    role_counts = {}
    for role in UserRole:
        count = db.query(func.count(User.id)).filter(User.role == role).scalar()
        role_counts[role.value] = count

    # Subscription stats
    subscription_counts = {}
    for status in SubscriptionStatus:
        count = db.query(func.count(User.id)).filter(User.subscription_status == status).scalar()
        subscription_counts[status.value] = count

    return {
        "total_users": total_users,
        "active_users": active_users,
        "admin_count": admin_count,
        "new_this_month": new_this_month,
        "role_counts": role_counts,
        "subscription_counts": subscription_counts
    }


@router.post("", response_model=UserResponse)
async def create_user(
    user_data: UserAdminCreate,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """
    Create new user (admin only)
    Requires ADMIN role
    """

    # Check if email already exists
    if db.query(User).filter(User.email == user_data.email).first():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )

    # Check if username already exists
    if db.query(User).filter(User.username == user_data.username).first():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already taken"
        )

    # Generate random password if not provided
    password = user_data.password
    if not password:
        # Generate strong random password
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
        password = ''.join(secrets.choice(alphabet) for _ in range(16))

    # Create user
    new_user = User(
        email=user_data.email,
        username=user_data.username,
        first_name=user_data.first_name,
        last_name=user_data.last_name,
        hashed_password=get_password_hash(password),
        role=user_data.role,
        is_active=user_data.is_active,
        is_verified=user_data.is_verified,
        can_write_blog=user_data.can_write_blog,
        can_moderate=user_data.can_moderate,
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return new_user


@router.get("/{user_id}", response_model=UserResponse)
async def get_user_by_id(
    user_id: int,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """
    Get single user by ID
    Requires ADMIN role
    """

    user = db.query(User).filter(User.id == user_id).first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    return user


@router.put("/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: int,
    user_update: UserAdminUpdate,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """
    Update user (admin-only fields)
    Requires ADMIN role
    """

    user = db.query(User).filter(User.id == user_id).first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    # Prevent admin from deactivating themselves
    if user.id == current_user.id and user_update.is_active is False:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot deactivate your own account"
        )

    # Prevent admin from removing their own admin role
    if user.id == current_user.id and user_update.is_admin is False:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot remove your own admin privileges"
        )

    # Update fields
    update_data = user_update.dict(exclude_unset=True)
    for field, value in update_data.items():
        setattr(user, field, value)

    user.updated_at = datetime.utcnow()

    db.commit()
    db.refresh(user)

    return user


@router.delete("/{user_id}")
async def delete_user(
    user_id: int,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """
    Delete user account
    Requires ADMIN role
    """

    user = db.query(User).filter(User.id == user_id).first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    # Prevent admin from deleting themselves
    if user.id == current_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete your own account"
        )

    db.delete(user)
    db.commit()

    return {"message": "User deleted successfully"}


@router.post("/bulk-update")
async def bulk_update_users(
    user_ids: List[int],
    updates: UserAdminUpdate,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """
    Bulk update multiple users
    Requires ADMIN role
    """

    # Prevent admin from modifying themselves in bulk
    if current_user.id in user_ids:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot modify your own account in bulk operations"
        )

    # Get all users
    users = db.query(User).filter(User.id.in_(user_ids)).all()

    if not users:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No users found with provided IDs"
        )

    # Update all users
    update_data = updates.dict(exclude_unset=True)
    updated_count = 0

    for user in users:
        for field, value in update_data.items():
            setattr(user, field, value)
        user.updated_at = datetime.utcnow()
        updated_count += 1

    db.commit()

    return {
        "message": f"Successfully updated {updated_count} users",
        "updated_count": updated_count
    }


@router.post("/bulk-delete")
async def bulk_delete_users(
    user_ids: List[int],
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """
    Bulk delete multiple users
    Requires ADMIN role
    """

    # Prevent admin from deleting themselves
    if current_user.id in user_ids:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete your own account"
        )

    # Get all users
    users = db.query(User).filter(User.id.in_(user_ids)).all()

    if not users:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No users found with provided IDs"
        )

    deleted_count = len(users)

    # Delete all users
    for user in users:
        db.delete(user)

    db.commit()

    return {
        "message": f"Successfully deleted {deleted_count} users",
        "deleted_count": deleted_count
    }
