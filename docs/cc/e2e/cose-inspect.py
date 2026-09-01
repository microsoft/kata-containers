#!/usr/bin/env python3
#
# Copyright (c) Microsoft Corporation.
#
# SPDX-License-Identifier: Apache-2.0
#
# Decode a signed policy fragment (COSE_Sign1) so a demo can show what the guest
# is actually handed, rather than asserting what is inside it.
#
# Why this exists at all: the fragment is the one artifact in the flow that the
# host fetches from a registry and passes into the guest. Everything the guest
# decides about it -- who signed it, which feed it claims, what SVN it carries,
# and what Rego it would add -- comes from these bytes. Printing them is the
# difference between "the fragment says svn 2" and "we told you it says svn 2".
#
# It deliberately carries its own CBOR reader instead of depending on cbor2:
# the node this runs on has no such package, and a demo that needs a pip install
# to explain itself is a demo with a dependency on the internet. Only the subset
# COSE needs is implemented -- ints, byte/text strings, arrays, maps, tags,
# simple values -- and anything else raises rather than guessing.
#
# Usage:
#   cose-inspect.py <file.cose|file.hex> [--payload] [--json]
#
#   --payload   print the payload (the Rego module) instead of the summary
#   --json      print the decoded header fields as JSON

import binascii
import json
import sys

# COSE header labels (RFC 9052 s3.1) and the SCITT/CWT labels the reference
# monitor reads. Anything not named here is printed by its numeric label.
COSE_LABELS = {
    1: "alg",
    3: "content type",
    4: "kid",
    15: "CWT claims",
    33: "x5chain",
}
# RFC 8392 CWT claim keys. The reference monitor reads the issuer and the feed
# from here, so they are worth naming rather than printing as 1 and 2.
CWT_CLAIMS = {1: "issuer", 2: "feed", 3: "audience", 6: "issued at"}
ALG_NAMES = {-7: "ES256", -35: "ES384", -36: "ES512", -8: "EdDSA"}


class CborError(Exception):
    pass


class Reader:
    def __init__(self, data):
        self.d = data
        self.i = 0

    def byte(self):
        if self.i >= len(self.d):
            raise CborError("truncated CBOR")
        b = self.d[self.i]
        self.i += 1
        return b

    def take(self, n):
        if self.i + n > len(self.d):
            raise CborError("truncated CBOR")
        out = self.d[self.i:self.i + n]
        self.i += n
        return out

    def arg(self, info):
        # Additional-information encoding: <24 is the value itself, 24..27 are
        # 1/2/4/8-byte follow-ons, 31 is the indefinite-length marker.
        if info < 24:
            return info
        if info == 24:
            return self.byte()
        if info in (25, 26, 27):
            return int.from_bytes(self.take(1 << (info - 24)), "big")
        if info == 31:
            return None
        raise CborError("reserved additional information %d" % info)

    def value(self):
        first = self.byte()
        major, info = first >> 5, first & 0x1F
        if major == 0:
            return self.arg(info)
        if major == 1:
            return -1 - self.arg(info)
        if major in (2, 3):
            n = self.arg(info)
            if n is None:
                raise CborError("indefinite-length strings are not supported")
            raw = self.take(n)
            return raw if major == 2 else raw.decode("utf-8", "replace")
        if major == 4:
            n = self.arg(info)
            if n is None:
                raise CborError("indefinite-length arrays are not supported")
            return [self.value() for _ in range(n)]
        if major == 5:
            n = self.arg(info)
            if n is None:
                raise CborError("indefinite-length maps are not supported")
            out = {}
            for _ in range(n):
                k = self.value()
                out[k if isinstance(k, (int, str)) else repr(k)] = self.value()
            return out
        if major == 6:
            self.arg(info)  # tag number: COSE_Sign1 is 18, and the content is
            return self.value()  # what matters, so unwrap rather than record it
        if major == 7:
            if info == 20:
                return False
            if info == 21:
                return True
            if info == 22:
                return None
            raise CborError("unsupported simple value %d" % info)
        raise CborError("unsupported major type %d" % major)


def label_name(label):
    return COSE_LABELS.get(label, str(label))


def render(label, value):
    if label == 1 and isinstance(value, int):
        return "%s (%d)" % (ALG_NAMES.get(value, "alg %d" % value), value)
    if label == 15 and isinstance(value, dict):
        return ", ".join(
            "%s=%s" % (CWT_CLAIMS.get(k, k), v) for k, v in sorted(value.items(), key=str)
        )
    if isinstance(value, bytes):
        # x5chain and kid are large and binary; report shape, not contents.
        return "<%d bytes>" % len(value)
    if isinstance(value, list):
        return "[%s]" % ", ".join(
            "<%d bytes>" % len(v) if isinstance(v, bytes) else str(v) for v in value
        )
    return str(value)


def load(path):
    with open(path, "rb") as f:
        raw = f.read()
    # sign-fragment emits hex; the OCI artifact carries the raw bytes. Accept
    # either so the demo can decode whichever form it has at hand.
    stripped = b"".join(raw.split())
    if stripped and all(c in b"0123456789abcdefABCDEF" for c in stripped):
        return binascii.unhexlify(stripped)
    return raw


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    flags = {a for a in sys.argv[1:] if a.startswith("--")}
    if len(args) != 1:
        print("usage: cose-inspect.py <file.cose|file.hex> [--payload] [--json]",
              file=sys.stderr)
        return 2

    envelope = Reader(load(args[0])).value()
    if not isinstance(envelope, list) or len(envelope) != 4:
        raise CborError("not a COSE_Sign1: expected a 4-element array")
    protected_bstr, unprotected, payload, signature = envelope
    protected = Reader(protected_bstr).value() if protected_bstr else {}

    if "--payload" in flags:
        sys.stdout.write(payload.decode("utf-8", "replace"))
        return 0

    fields = {label_name(k): render(k, v) for k, v in protected.items()}
    if "--json" in flags:
        print(json.dumps(fields, indent=2, sort_keys=True))
        return 0

    print("COSE_Sign1")
    print("  protected header (signed — changing any of this breaks the signature):")
    for k in sorted(fields, key=str):
        print("    %-14s %s" % (k, fields[k]))
    if unprotected:
        print("  unprotected header (NOT signed):")
        for k, v in unprotected.items():
            print("    %-14s %s" % (label_name(k), render(k, v)))
    print("  payload          %d bytes of Rego" % len(payload))
    print("  signature        %d bytes" % len(signature))
    return 0


if __name__ == "__main__":
    sys.exit(main())
