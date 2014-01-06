"""OpenLDAP support.

These objects provide support for service implementations based on
`OpenLDAP <http://www.openldap.org/>`_.

"""

__copyright__ = "Copyright (C) 2014 Ivan D Vasin"
__docformat__ = "restructuredtext"

import os as _os
import subprocess as _subprocess

import pkg_resources as _pkg_resources

try:
    _pkg_resources.require('spruce-ldap [openldap]')
except _pkg_resources.ResolutionError:
    pass
else:
    for searchpath in _os.environ['PATH'].split(_os.pathsep):
        slapd_path = _os.path.join(searchpath.strip('"'), 'slapd')
        try:
            slapd_output = _subprocess.check_output((slapd_path, '-VV'),
                                                    stderr=_subprocess.STDOUT)
        except OSError:
            continue
        except _subprocess.CalledProcessError as exc:
            slapd_output = exc.output

        if 'openldap' in slapd_output.lower():
            from ._services import *
        break
