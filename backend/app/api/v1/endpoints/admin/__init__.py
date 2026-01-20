# Admin endpoints module
from .users import router as users_router
from .plugins import router as plugins_router
from .system import router as system_router
from .activities import router as activities_router
from .stats import router as stats_router

__all__ = [
    "users_router",
    "plugins_router",
    "system_router",
    "activities_router",
    "stats_router"
]
