"""Security label lattices

Confidentiality (Myers-Liskov style): how protected data is
    public < internal < confidential

Integrity (Biba style): how trustworthy data is
    untrusted < user < high
"""

from enum import IntEnum


class Confidentiality(IntEnum):
    """How protected a data value is (Myers-Liskov ordering)"""

    PUBLIC = 0
    INTERNAL = 1
    CONFIDENTIAL = 2


class Integrity(IntEnum):
    """How trustworthy a data value is (Biba ordering)"""

    UNTRUSTED = 0
    USER = 1
    HIGH = 2
