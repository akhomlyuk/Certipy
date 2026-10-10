"""
Tests for Cyrillic / non-latin-1 support.

The whole point of `certipy.lib.cyrillic` is that a Russian AD lab works the
same as an English one. These tests pin down the three independent breakages
that got in the way, plus the ASCII behaviour that must NOT change.
"""

import os

import pytest

from certipy.lib.cyrillic import is_patched

CYR_USER = "Пётр"
CYR_REALM = "КОРПОРАЦИЯ.РФ"
LATIN_USER = "peter"
LATIN_REALM = "CORP.EXAMPLE"


# --- the patches are actually installed ------------------------------------


def test_patches_are_installed():
    assert is_patched()


# --- bug 1: impacket.structure.Structure.ENCODING is latin-1 --------------


def test_impacket_structure_encoding_is_utf8():
    from impacket.structure import Structure

    assert Structure.ENCODING == "utf-8"


def test_ccache_counted_octet_string_serialises_cyrillic():
    from impacket.krb5.ccache import CountedOctetString

    cos = CountedOctetString()
    cos["length"] = len(CYR_USER.encode("utf-8"))
    cos["data"] = CYR_USER

    assert cos.getData() == b"\x00\x00\x00\x08" + CYR_USER.encode("utf-8")


# --- bug 2: six.b() encodes with latin-1 ---------------------------------


def test_six_b_encodes_cyrillic_as_utf8():
    import six

    assert six.b(CYR_USER) == CYR_USER.encode("utf-8")


def test_ccache_principal_prettyprint_cyrillic():
    from impacket.krb5.ccache import Principal

    pr = Principal()
    pr.header["name_type"] = 1
    pr.header["num_components"] = 1
    pr.realm = _counted(CYR_REALM)
    pr.components = [_counted(CYR_USER)]

    assert pr.prettyPrint() == (
        CYR_USER.encode("utf-8") + b"@" + CYR_REALM.encode("utf-8")
    )


def _counted(value):
    from impacket.krb5.ccache import CountedOctetString

    raw = value.encode("utf-8")
    cos = CountedOctetString()
    cos["length"] = len(raw)
    cos["data"] = raw
    return cos


# --- bug 3: Principal.fromPrincipal counted CHARACTERS, not BYTES ---------
# This was the silent one: the file was written without error but read back
# truncated, which is why `certipy auth` claimed to save a ccache it never
# actually saved.


@pytest.mark.parametrize(
    "user,realm",
    [(CYR_USER, CYR_REALM), (LATIN_USER, LATIN_REALM)],
)
def test_ccache_write_read_roundtrip(tmp_path, user, realm):
    from impacket.krb5 import types as krb5_types
    from impacket.krb5.ccache import CCache

    ccache = CCache()
    ccache.setDefaultHeader()

    principal = CCachePrincipalFactory(user, realm)
    ccache.principal = principal

    path = os.path.join(tmp_path, f"{user}.ccache")
    ccache.saveFile(path)

    loaded = CCache.loadFile(path)
    assert loaded.principal.realm["data"].decode("utf-8") == realm
    assert [c["data"].decode("utf-8") for c in loaded.principal.components] == [user]


def CCachePrincipalFactory(user, realm):
    from impacket.krb5 import types as krb5_types
    from impacket.krb5.ccache import Principal

    parsed = krb5_types.Principal(f"{user}@{realm}")
    pr = Principal()
    pr.fromPrincipal(parsed)
    return pr


# --- certipy's own ASN.1: realm/cname/sname must be utf-8 ---------------


def test_certipy_kerberos_string_is_utf8():
    from certipy.lib import structs

    assert structs.KerberosString._encoding == "utf-8"


def test_kdc_req_body_realm_field_uses_utf8_spec():
    """The real wiring: KdcReqBody.realm must point at the utf-8 subclass."""
    from certipy.lib import structs

    realm_field = next(f for f in structs.KdcReqBody._fields if f[0] == "realm")

    assert realm_field[1] is structs.KerberosString


def test_ticket_realm_field_uses_utf8_spec():
    from certipy.lib import structs

    realm_field = next(f for f in structs.Ticket._fields if f[0] == "realm")

    assert realm_field[1] is structs.KerberosString


def _realm_holder(realm):
    """A Sequence shaped like KdcReqBody's realm slot."""
    from asn1crypto import core

    from certipy.lib import structs

    class Holder(core.Sequence):
        _fields = [("realm", structs.KerberosString, {"tag_type": 0, "tag": 2})]

    holder = Holder()
    holder["realm"] = realm
    return holder


def test_realm_encodes_cyrillic_as_utf8():
    assert _realm_holder(CYR_REALM).dump() == _der(CYR_REALM)


def test_principal_name_encodes_cyrillic():
    from certipy.lib import structs

    name = structs.PrincipalName()
    name["name-type"] = 1
    name["name-string"] = [CYR_USER, "krbtgt"]

    assert CYR_USER.encode("utf-8") in name.dump()


def test_structs_no_longer_use_raw_general_string():
    """Every Kerberos string slot must point at the utf-8 subclass."""
    from certipy.lib import structs

    assert structs.SequenceOfKerberosString._child_spec is structs.KerberosString


def _der(value):
    """DER of a KerberosString -- GeneralString tag 0x1b, explicit length."""
    return _der_using("utf-8", value)


def _der_using(encoding, value):
    raw = value.encode(encoding)
    body = b"\x1b" + _length(len(raw)) + raw
    return b"\x30" + _length(len(body)) + body


def _length(n):
    if n < 0x80:
        return bytes([n])
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


# --- regression: ASCII and latin-1 names must be unaffected --------------


def test_ascii_realm_encodes_identically():
    """latin-1 and utf-8 agree on ASCII, so nothing shifts for english ADs."""
    assert _realm_holder(LATIN_REALM).dump() == _der(LATIN_REALM)


def test_latin1_accented_realm_now_goes_out_as_utf8():
    """
    An accented latin-1 name changes -- deliberately.

    latin-1 and utf-8 agree below U+0080, so ASCII is untouched (see
    test_ascii_realm_encodes_identically). Above it they diverge, and utf-8 is
    the correct choice: Windows encodes Kerberos strings as UTF-8 even when the
    name happens to be representable in latin-1. A C-umlaut realm now goes out
    as two bytes (``\\xc3\\x96``) instead of one (``\\xd6``).
    """
    value = "CÖRP"

    as_utf8 = _der_using("utf-8", value)
    as_latin1 = _der_using("latin-1", value)

    assert _realm_holder(value).dump() == as_utf8
    # and it is no longer the latin-1 form stock Certipy would have produced
    assert as_utf8 != as_latin1
    assert len(as_utf8) == len(as_latin1) + 1


# --- version guard -------------------------------------------------------


def test_impacket_version_supports_utf8_kerberos_string():
    """pyasn1 needs no patch, but only on impacket >= 0.13."""
    from importlib.metadata import version

    from certipy.lib.cyrillic import MIN_IMPACT_VERSION

    parts = tuple(int(p) for p in version("impacket").split(".")[:3] if p.isdigit())
    assert parts >= MIN_IMPACT_VERSION


def test_pyasn1_kerberos_string_is_utf8_without_patching_pyasn1():
    from impacket.krb5.asn1 import KerberosString

    assert KerberosString.encoding == "utf-8"


# --- the path that actually broke: reading back a ccache -----------------


def test_get_kerberos_principal_reads_cyrillic_ccache(tmp_path, monkeypatch):
    """
    `certipy unpac` resolves credentials through this function.

    Before the fromPrincipal fix the ccache was written too short, so this
    read back a truncated name even though `certipy auth` had reported the
    file as saved.
    """
    from impacket.krb5.ccache import CCache

    from certipy.lib.target import get_kerberos_principal

    ccache = CCache()
    ccache.setDefaultHeader()
    ccache.principal = CCachePrincipalFactory(CYR_USER, CYR_REALM)

    path = os.path.join(tmp_path, "Пётр.ccache")
    ccache.saveFile(path)
    monkeypatch.setenv("KRB5CCNAME", path)

    assert get_kerberos_principal() == (CYR_USER, CYR_REALM)
