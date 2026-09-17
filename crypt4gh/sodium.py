"""Deprecated alias for :mod:`crypt4gh.crypto`, to be removed in version 2."""

import warnings

from .crypto import *  # noqa: F403
from .crypto import __all__  # noqa: F401

warnings.warn(
    "crypt4gh.sodium is deprecated, use crypt4gh.crypto",
    DeprecationWarning,
    stacklevel=2,
)
