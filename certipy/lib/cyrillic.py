"""
Cyrillic (and other non-latin-1) support for Certipy's dependency stack.

Why this module exists
----------------------
Active Directory happily stores and returns names like ``Пётр@КОРПОРАЦИЯ.РФ``
in UTF-8, but three layers underneath Certipy still assume everything is
latin-1 and blow up -- or, worse, silently truncate:

1. ``impacket.structure.Structure.ENCODING`` is ``'latin-1'``, so every
   ``str`` assigned into a structure field raises ``UnicodeEncodeError`` on
   the way out in ``getData()``.  This is what breaks writing a ccache.

2. ``six.b()`` is hardcoded to ``latin-1``.  ``impacket.krb5.ccache`` does
   ``from six import b`` and calls it in ``Principal.prettyPrint()``.

3. ``impacket.krb5.ccache.Principal.fromPrincipal`` stores
   ``len(principal.realm)`` -- the number of *characters* -- into a field that
   must hold a number of *bytes*.  For a latin-1 name these coincide; for
   ``КОРПОРАЦИЯ.РФ`` it writes 13 where the payload is 25 bytes.  Nothing
   raises, the file is simply written too short, and reading it back yields a
   truncated principal.  This is the quiet one, and the reason ``certipy auth``
   would report a saved ccache that did not actually round-trip.

What is deliberately NOT patched here
-------------------------------------
- ``pyasn1``:  ``impacket.krb5.asn1.KerberosString`` sets
  ``encoding = 'utf-8'`` upstream as of impacket 0.13, so Kerberos strings
  already serialise correctly.  Patching ``pyasn1.type.char`` would change
  ``GeneralString`` for every consumer in the process, including the ones
  where latin-1 is what the ASN.1 spec actually mandates.

- ``asn1crypto``:  patching ``core.AbstractString._encoding`` globally would
  likewise redefine ``NumericString``/``PrintableString``/``VisibleString``,
  which are genuinely latin-1 per X.680.  Certipy is the only thing that
  mislabels Kerberos strings as ``core.GeneralString``, so the fix belongs in
  ``certipy.lib.structs`` -- see ``KerberosString`` there.

Compatibility
-------------
All three patches are strictly additive for ASCII: latin-1 and UTF-8 encode
identical bytes below U+0080, so an English lab sees byte-for-byte the same
behaviour as stock Certipy.  See ``tests/test_cyrillic.py``.

Importing :mod:`certipy` installs the patches.  Set the environment variable
``CERTIPY_NO_CYRILLIC=1`` to opt out and get stock behaviour.
"""

import os
from typing import Union

from certipy.lib.logger import logging

# impacket >= 0.13 ships the KerberosString utf-8 fix upstream. Below that,
# Kerberos names stay latin-1 and the guard below will say so.
MIN_IMPACT_VERSION = (0, 13, 0)

_ORIGINAL_ENCODING: str = "latin-1"
_TARGET_ENCODING: str = "utf-8"


def _encode_utf8(value: Union[bytes, str]) -> bytes:
    """utf-8 encode, passing bytes through untouched."""
    if isinstance(value, bytes):
        return value
    return value.encode(_TARGET_ENCODING)


def _patch_impacket_structure() -> None:
    """Structure.ENCODING drives ``self.b`` for every str->bytes conversion."""
    from impacket.structure import Structure

    # setattr rather than assignment: impacket types ENCODING as a Literal,
    # so a plain assignment is a type error even though it works at runtime.
    setattr(Structure, "ENCODING", _TARGET_ENCODING)


def _patch_six_b() -> None:
    """
    ``six.b`` is latin-1 by contract. ``impacket.krb5.ccache`` binds it at
    import time (``from six import b``), so both the module attribute and the
    already-bound name need updating.
    """
    import six
    from impacket.krb5 import ccache as impacket_ccache

    six.b = _encode_utf8
    impacket_ccache.b = _encode_utf8


def _patch_principal_from_principal() -> None:
    """
    Count bytes, not characters.

    ``CountedOctetString['length']`` must describe the serialised payload.
    ``len(str)`` is only ever equal to that for ASCII.
    """
    from impacket.krb5.ccache import CountedOctetString, Principal

    def from_principal(self: "Principal", principal: object) -> None:
        self.header["name_type"] = principal.type  # type: ignore[attr-defined]
        self.header["num_components"] = len(principal.components)  # type: ignore[attr-defined]
        self.realm = _counted(principal.realm)  # type: ignore[attr-defined]
        self.components = [  # type: ignore[attr-defined]
            _counted(component) for component in principal.components  # type: ignore[attr-defined]
        ]

    def _counted(value: Union[bytes, str]) -> "CountedOctetString":
        raw = _encode_utf8(value)
        counted = CountedOctetString()
        counted["length"] = len(raw)
        counted["data"] = raw
        return counted

    Principal.fromPrincipal = from_principal


def is_patched() -> bool:
    """True when every patch is in place."""
    import six
    from impacket.krb5 import ccache as impacket_ccache
    from impacket.structure import Structure

    return (
        getattr(Structure, "ENCODING", None) == _TARGET_ENCODING
        and six.b is _encode_utf8
        and impacket_ccache.b is _encode_utf8
    )


def _warn_if_impacket_too_old() -> None:
    from importlib.metadata import PackageNotFoundError, version

    try:
        raw = version("impacket")
    except PackageNotFoundError:
        return

    parts = tuple(int(p) for p in raw.split(".")[:3] if p.isdigit())
    if parts and parts < MIN_IMPACT_VERSION:
        logging.warning(
            f"impacket {raw} is older than {'.'.join(map(str, MIN_IMPACT_VERSION))}; "
            "Kerberos strings may still be latin-1 encoded. Pin impacket>=0.13."
        )


def apply() -> bool:
    """Install every patch. Idempotent. Returns True if patches are active."""
    _patch_impacket_structure()
    _patch_six_b()
    _patch_principal_from_principal()
    _warn_if_impacket_too_old()
    logging.debug(
        f"Cyrillic support active ({_ORIGINAL_ENCODING} -> {_TARGET_ENCODING})"
    )
    return True


def _disabled() -> bool:
    return os.getenv("CERTIPY_NO_CYRILLIC", "").strip().lower() in ("1", "true", "yes")


if not _disabled():
    apply()
