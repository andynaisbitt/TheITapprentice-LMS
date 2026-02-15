# Backend/app/api/v1/endpoints/navigation/public.py
"""Public navigation endpoints"""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.core.config import settings
from app.api.v1.services.navigation.models import MenuItem
from app.api.v1.services.navigation.schemas import NavigationResponse, MenuItemResponse
from app.api.v1.services.site_settings.models import SiteSettings

router = APIRouter()


def get_lms_plugin_links() -> list[MenuItemResponse]:
    """Generate navigation links for enabled LMS plugins"""
    lms_links = []
    base_id = 90000  # Use high IDs to avoid conflicts with DB items

    # Check if any LMS plugin is enabled
    tutorials_enabled = settings.PLUGINS_ENABLED.get("tutorials", False)
    courses_enabled = settings.PLUGINS_ENABLED.get("courses", False)
    quizzes_enabled = settings.PLUGINS_ENABLED.get("quizzes", False)
    typing_game_enabled = settings.PLUGINS_ENABLED.get("typing_game", False)

    if not (tutorials_enabled or courses_enabled or quizzes_enabled or typing_game_enabled):
        return []

    # Create parent "Learn" menu item
    learn_children = []

    if courses_enabled:
        learn_children.append(MenuItemResponse(
            id=base_id + 1,
            label="Courses",
            url="/courses",
            order=1,
            parent_id=base_id,
            visible=True,
            show_in_header=True,
            show_in_footer=False,
            target_blank=False,
            created_at=None,
            updated_at=None,
            children=[]
        ))

    if tutorials_enabled:
        learn_children.append(MenuItemResponse(
            id=base_id + 2,
            label="Tutorials",
            url="/tutorials",
            order=2,
            parent_id=base_id,
            visible=True,
            show_in_header=True,
            show_in_footer=False,
            target_blank=False,
            created_at=None,
            updated_at=None,
            children=[]
        ))

    if quizzes_enabled:
        learn_children.append(MenuItemResponse(
            id=base_id + 3,
            label="Quizzes",
            url="/quizzes",
            order=3,
            parent_id=base_id,
            visible=True,
            show_in_header=True,
            show_in_footer=False,
            target_blank=False,
            created_at=None,
            updated_at=None,
            children=[]
        ))

    if typing_game_enabled:
        learn_children.append(MenuItemResponse(
            id=base_id + 4,
            label="Typing Practice",
            url="/typing-practice",
            order=4,
            parent_id=base_id,
            visible=True,
            show_in_header=True,
            show_in_footer=False,
            target_blank=False,
            created_at=None,
            updated_at=None,
            children=[]
        ))

    # Only add Learn menu if there are children
    if learn_children:
        learn_menu = MenuItemResponse(
            id=base_id,
            label="Learn",
            url="/tutorials",  # Default URL for Learn
            order=50,  # Position in middle of nav
            parent_id=None,
            visible=True,
            show_in_header=True,
            show_in_footer=False,
            target_blank=False,
            created_at=None,
            updated_at=None,
            children=learn_children
        )
        lms_links.append(learn_menu)

    return lms_links


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

    # Check if LMS navigation is enabled in site settings
    site_settings = db.query(SiteSettings).first()
    show_lms_nav = True  # Default to True

    if site_settings and hasattr(site_settings, 'show_lms_navigation'):
        show_lms_nav = site_settings.show_lms_navigation

    # Add LMS plugin links to header if enabled
    if show_lms_nav:
        lms_links = get_lms_plugin_links()
        # Insert LMS links before the last item (usually "About" or "Contact")
        if lms_links and header_items:
            # Find the right position (after Blog, before About)
            insert_position = len(header_items) - 1 if len(header_items) > 1 else len(header_items)
            for link in lms_links:
                header_items.insert(insert_position, link)

    return {
        "header_items": header_items,
        "footer_items": footer_items
    }
