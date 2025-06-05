# Store singleton-like application state

# Prevent circular imports
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from . import tab_view

tabview: Optional["tab_view.TabView"] = None
