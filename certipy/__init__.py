"""
Certipy: Active Directory Certificate Services enumeration and abuse.

Importing this package installs the Cyrillic compatibility patches in
:mod:`certipy.lib.cyrillic`. Set ``CERTIPY_NO_CYRILLIC=1`` to skip them.
"""

# Importing the module applies the patches, or opts out if
# CERTIPY_NO_CYRILLIC is set. See certipy/lib/cyrillic.py.
from certipy.lib import cyrillic  # noqa: F401
