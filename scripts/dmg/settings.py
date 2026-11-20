# dmgbuild settings for the selfguard DMG: the window you see when you open it.
# Used by scripts/notarize-app.sh:
#
#   dmgbuild -s scripts/dmg/settings.py -D app=<selfguard.app> -D root=<repo> "selfguard <version>" <dmg>
#
# The background is scripts/dmg/background.html rendered by scripts/dmg/render.mjs; the window
# size and icon centers below must match the ones in that page.
import os.path

app = defines["app"]  # noqa: F821 (dmgbuild provides `defines`)
root = defines["root"]  # noqa: F821

files = [app]
symlinks = {"Applications": "/Applications"}
icon = os.path.join(root, "src", "assets", "selfguard.icns")
# @2x next to it is picked up automatically (one HiDPI TIFF).
background = os.path.join(root, "macos", "Resources", "dmg", "background.png")

format = "UDZO"
filesystem = "HFS+"

window_rect = ((200, 120), (640, 420))
default_view = "icon-view"
show_status_bar = False
show_tab_view = False
show_toolbar = False
show_pathbar = False
show_sidebar = False
show_icon_preview = False

icon_size = 112
text_size = 13
icon_locations = {
    os.path.basename(app): (170, 200),
    "Applications": (470, 200),
}
