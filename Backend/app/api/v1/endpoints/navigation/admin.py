# Backend/app/api/v1/endpoints/navigation/admin.py
"""Admin navigation endpoints"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List
from app.core.database import get_db
from app.auth.dependencies import require_admin
from app.api.v1.services.navigation.models import MenuItem
from app.api.v1.services.navigation.schemas import (
    MenuItemResponse,
    MenuItemCreate,
    MenuItemUpdate
)

router = APIRouter()


@router.get("/admin/navigation", response_model=List[MenuItemResponse])
def get_all_menu_items(
    db: Session = Depends(get_db),
    current_user = Depends(require_admin)
):
    """Get all menu items (admin only)"""
    items = db.query(MenuItem).order_by(MenuItem.order).all()
    return items


@router.get("/admin/navigation/{item_id}", response_model=MenuItemResponse)
def get_menu_item(
    item_id: int,
    db: Session = Depends(get_db),
    current_user = Depends(require_admin)
):
    """Get single menu item by ID"""
    item = db.query(MenuItem).filter(MenuItem.id == item_id).first()
    if not item:
        raise HTTPException(status_code=404, detail="Menu item not found")
    return item


@router.post("/admin/navigation", response_model=MenuItemResponse)
def create_menu_item(
    item_data: MenuItemCreate,
    db: Session = Depends(get_db),
    current_user = Depends(require_admin)
):
    """Create new menu item"""
    new_item = MenuItem(**item_data.model_dump())
    db.add(new_item)
    db.commit()
    db.refresh(new_item)
    return new_item


@router.put("/admin/navigation/{item_id}", response_model=MenuItemResponse)
def update_menu_item(
    item_id: int,
    item_data: MenuItemUpdate,
    db: Session = Depends(get_db),
    current_user = Depends(require_admin)
):
    """Update menu item"""
    item = db.query(MenuItem).filter(MenuItem.id == item_id).first()
    if not item:
        raise HTTPException(status_code=404, detail="Menu item not found")

    update_data = item_data.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(item, field, value)

    db.commit()
    db.refresh(item)
    return item


@router.delete("/admin/navigation/{item_id}")
def delete_menu_item(
    item_id: int,
    db: Session = Depends(get_db),
    current_user = Depends(require_admin)
):
    """Delete menu item"""
    item = db.query(MenuItem).filter(MenuItem.id == item_id).first()
    if not item:
        raise HTTPException(status_code=404, detail="Menu item not found")

    db.delete(item)
    db.commit()
    return {"message": "Menu item deleted successfully"}


@router.post("/admin/navigation/reorder")
def reorder_menu_items(
    item_orders: List[dict],
    db: Session = Depends(get_db),
    current_user = Depends(require_admin)
):
    """Bulk reorder menu items

    Expects: [{"id": 1, "order": 0}, {"id": 2, "order": 1}, ...]
    """
    for item_data in item_orders:
        item = db.query(MenuItem).filter(MenuItem.id == item_data["id"]).first()
        if item:
            item.order = item_data["order"]

    db.commit()
    return {"message": "Menu items reordered successfully"}
