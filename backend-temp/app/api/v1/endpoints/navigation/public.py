# Backend/app/api/v1/endpoints/navigation/public.py
"""Public navigation endpoints"""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.api.v1.services.navigation.models import MenuItem
from app.api.v1.services.navigation.schemas import NavigationResponse, MenuItemResponse

router = APIRouter()


def build_menu_tree(items):
    """Build hierarchical menu structure with children"""
    # Convert SQLAlchemy objects to dict format
    items_dict = {}
    for item in items:
        items_dict[item.id] = MenuItemResponse(
            id=item.id,
            label=item.label,
            url=item.url,
            order=item.order,
            parent_id=item.parent_id,
            visible=item.visible,
            show_in_header=item.show_in_header,
            show_in_footer=item.show_in_footer,
            target_blank=item.target_blank,
            created_at=item.created_at,
            updated_at=item.updated_at,
            children=[]
        )

    # Build tree structure
    root_items = []
    for item in items:
        item_obj = items_dict[item.id]
        if item.parent_id and item.parent_id in items_dict:
            # This is a child item - add to parent's children
            items_dict[item.parent_id].children.append(item_obj)
        else:
            # This is a root item
            root_items.append(item_obj)

    return root_items


@router.get("/navigation", response_model=NavigationResponse)
def get_navigation(db: Session = Depends(get_db)):
    """Get all visible navigation items with hierarchical structure (public endpoint)"""

    # Get all header items (including children)
    header_items_query = db.query(MenuItem).filter(
        MenuItem.visible == True,
        MenuItem.show_in_header == True
    ).order_by(MenuItem.order).all()

    # Get all footer items (including children)
    footer_items_query = db.query(MenuItem).filter(
        MenuItem.visible == True,
        MenuItem.show_in_footer == True
    ).order_by(MenuItem.order).all()

    # Build hierarchical structures
    header_items = build_menu_tree(header_items_query)
    footer_items = build_menu_tree(footer_items_query)

    return {
        "header_items": header_items,
        "footer_items": footer_items
    }
