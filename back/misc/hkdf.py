# Based on https://github.com/orcasgit/django-fernet-fields
# BSD 3-Clause "New" or "Revised" License

# Copyright (c) 2015 ORCAS, Inc
# All rights reserved.

# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:

#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above
#       copyright notice, this list of conditions and the following
#       disclaimer in the documentation and/or other materials provided
#       with the distribution.
#     * Neither the name of the author nor the names of other
#       contributors may be used to endorse or promote products derived
#       from this software without specific prior written permission.

# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import base64
import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.utils.encoding import force_bytes

backend = default_backend()
info = b"django-fernet-fields"

# Get salt from settings, or use a default for backwards compatibility
# but warn that this is insecure
def get_fernet_salt():
    if hasattr(settings, 'FERNET_SALT') and settings.FERNET_SALT:
        return settings.FERNET_SALT
    else:
        import warnings
        warnings.warn(
            "FERNET_SALT is not configured in settings. Using default salt, which is insecure. "
            "Please set FERNET_SALT in your settings file.",
            category=RuntimeWarning
        )
        # For backwards compatibility, use the old static salt
        return b"django-fernet-fields-hkdf-salt"

# Get the salt from settings
salt = get_fernet_salt()


def derive_fernet_key(input_key):
    """Derive a 32-bit b64-encoded Fernet key from arbitrary input key."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=info,
        backend=backend,
    )
    return base64.urlsafe_b64encode(hkdf.derive(force_bytes(input_key)))
