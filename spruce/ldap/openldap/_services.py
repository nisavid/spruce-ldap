"""OpenLDAP services."""

__copyright__ = "Copyright (C) 2014 Ivan D Vasin"
__docformat__ = "restructuredtext"

from base64 import b64encode as _b64encode
from hashlib import sha1 as _sha1
import logging as _logging
import os as _os
import re as _re
from pipes import quote as _shquote
import subprocess as _subprocess
import sys as _sys
from tempfile import NamedTemporaryFile as _NamedTemporaryFile
from time import sleep as _sleep, time as _time

import ldap as _ldap
from spruce.pprint import indented as _indented

from .. import _services


class OpenLdapService(_services.ServiceImpl):

    """An OpenLDAP service."""

    @classmethod
    def create_basic(cls, uris, configloc, schemas, modules, config_password,
                     dbtype, dbdir, suffix, root_dn, root_password,
                     authz_map=None, access=(), index=(), pidfile=None):

        suffix_rdns = suffix.split(',')
        if len(suffix_rdns) > 1:
            suffix_org_dn = ','.join(suffix_rdns[-2:])
            suffix_orgunits_rdns = suffix_rdns[:-2]

            suffix_org_dn_match = cls._SUFFIX_ORG_DN_RE.match(suffix_org_dn)
            if not suffix_org_dn_match:
                raise ValueError('invalid suffix DN {!r}; expected one in'
                                  ' which the last two components match {!r}'
                                  .format(suffix, cls._SUFFIX_ORG_DN_RE))
            suffix_org = suffix_org_dn_match.group('org')

        if cls._PASSWORD_WITH_SCHEME_RE.match(root_password):
            root_password_configvalue = root_password
        else:
            root_password_salt = _os.urandom(4)
            root_password_configvalue = \
                '{SSHA}' + _b64encode(_sha1(root_password + root_password_salt)
                                       .digest()
                                      + root_password_salt)

        authz_map = authz_map or {}
        try:
            authz_map_items = authz_map.items()
        except AttributeError:
            authz_map_items = authz_map

        service = cls.create_minimal(uris=uris,
                                     configloc=configloc,
                                     schemas=schemas,
                                     config_password=config_password,
                                     pidfile=pidfile)
        svc_pid = service.start(fork=True)
        if svc_pid == 0:
            _sys.exit()

        try:
            config_client = service.client()
            config_client.simple_bind_s('cn=config', config_password)

            # configure SASL authentication
            config_client\
             .modify_s('cn=config',
                       ((_ldap.MOD_REPLACE, 'olcPasswordHash', '{CLEARTEXT}'),
                        (_ldap.MOD_REPLACE, 'olcAuthzRegexp',
                         tuple('{} {}'.format(match, replacement)
                               for match, replacement in authz_map_items)),
                        ))

            # configure primary backend database
            config_client\
             .add_s('cn=Module{0},cn=config',
                    (('objectClass', 'olcModuleList'),
                     ('olcModuleLoad', modules)))
            config_client\
             .add_s('olcDatabase={},cn=config'.format(dbtype),
                    (('objectClass',
                      'olc{}Config'.format(dbtype.capitalize())),
                     ('olcDatabase', dbtype),
                     ('olcDbDirectory', dbdir),
                     ('olcSuffix', suffix),
                     ('olcRootDN', root_dn),
                     ('olcRootPW', root_password_configvalue),
                     ))
            config_client\
             .modify_s('olcDatabase={1}hdb,cn=config',
                       ((_ldap.MOD_ADD, 'olcDbIndex', index),
                        (_ldap.MOD_REPLACE, 'olcAccess', access)))

            config_client.unbind_s()

            # initialize suffix
            suffix_rdns = suffix.split(',')
            if len(suffix_rdns) > 1:

                root_client = service.client()
                root_client.simple_bind_s(root_dn, root_password)

                root_client\
                 .add_s(suffix_org_dn,
                        (('objectClass', ('dcObject', 'organization')),
                         ('dc', suffix_org), ('o', suffix_org)))

                orgunit_dn = suffix_org_dn
                for orgunit_rdn in suffix_orgunits_rdns:
                    orgunit_dn = ','.join(orgunit_rdn, orgunit_dn)

                    _, orgunit = orgunit_dn.split('=')
                    root_client\
                     .add_s(suffix_org_dn,
                            (('objectClass', 'dcObject'),
                             ('objectClass', 'organizationalUnit'),
                             ('dc', orgunit), ('ou', orgunit)))

                root_client.unbind_s()

        finally:
            if service.status == _services.ServiceStatus('running'):
                service.stop()

        return service

    @classmethod
    def create_from_configfile(cls, uris, configfile, configdir):

        try:
            slaptest_output = \
                _subprocess.check_output(('slaptest', '-f', configfile, '-F',
                                          configdir),
                                         stderr=_subprocess.STDOUT)
        except _subprocess.CalledProcessError as exc:
            raise RuntimeError('invalid config file {!r}: slaptest returned'
                                ' exit code {} with output\n{}'
                                .format(configfile, exc.returncode,
                                        _indented(exc.output)))
        for line in slaptest_output.split('\n'):
            _logging.debug('slaptest: ' + line)

        return cls(uris, configloc=configdir)

    @classmethod
    def create_minimal(cls, uris, configloc, schemas, config_password,
                       pidfile=None):

        if _os.path.isdir(configloc) and _os.access(configloc, _os.W_OK):
            pass
        elif not _os.path.exists(configloc):
            try:
                _os.mkdir(configloc, 0700)
            except OSError as exc:
                raise RuntimeError('cannot create config dir {!r}: {}'
                                    .format(configloc, str(exc)))
        else:
            raise ValueError('invalid config dir {!r}; expecting a writable'
                              ' directory path'
                              .format(configloc))

        if cls._PASSWORD_WITH_SCHEME_RE.match(config_password):
            config_password_configvalue = config_password
        else:
            config_password_salt = _os.urandom(4)
            config_password_configvalue = \
                '{SSHA}' + _b64encode(_sha1(config_password
                                            + config_password_salt)
                                       .digest()
                                      + config_password_salt)

        if not pidfile:
            if _os.path.isdir(cls._PIDFILE_STD_DIR) \
                   and _os.access(cls._PIDFILE_STD_DIR, _os.W_OK):
                pidfile_dir = cls._PIDFILE_STD_DIR
            else:
                pidfile_dir = None
            pidfile_tmp = _NamedTemporaryFile(dir=pidfile_dir, prefix='slapd-',
                                              suffix='.pid')
            with pidfile_tmp:
                pass
            pidfile = pidfile_tmp.name

        configfile = _NamedTemporaryFile(delete=False)
        with configfile:
            for schema in schemas:
                configfile.write('include {}\n'.format(schema))
            configfile.write('pidfile {}\n'.format(pidfile))
            configfile.write('database config\n')
            configfile.write('rootpw {}\n'.format(config_password_configvalue))

        service = cls.create_from_configfile(uris=uris,
                                             configfile=configfile.name,
                                             configdir=configloc)
        _os.remove(configfile.name)
        return service

    def _start(self, fork=False):

        pidfilepath = None
        with open(_os.path.join(self.configloc, 'cn=config.ldif'), 'r') \
                 as config_ldif:
            for line in config_ldif.readlines():
                match = _re.match(r'olcPidFile:\s+(?P<pidfile>.*)\n', line)
                if match:
                    pidfilepath = match.group('pidfile')
                    break

        slapd_args = \
            ('slapd',
             '-h',
             ' '.join(self.uris),
             '-F',
             self.configloc,
             '-d',
             '239' if _logging.getLogger().isEnabledFor(_logging.DEBUG)
                   else '32768')

        if fork:
            slapd_proc = _subprocess.Popen(slapd_args, stdout=_subprocess.PIPE,
                                           stderr=_subprocess.STDOUT,
                                           close_fds=True)
            self._slapd_proc = slapd_proc
            slapd_output = ''
            slapd_started = False
            while not slapd_started:
                slapd_proc.poll()
                if slapd_proc.returncode is not None:
                    slapd_output += slapd_proc.stdout.read()
                    raise RuntimeError('cannot start OpenLDAP service via'
                                        ' {!r}: slapd returned exit code {}'
                                        ' with output\n{}'
                                        .format(' '.join(_shquote(arg)
                                                         for arg
                                                         in slapd_args),
                                                slapd_proc.returncode,
                                                slapd_output))

                current_poll_period_starttime = _time()
                while _time() - current_poll_period_starttime \
                      < self._START_POLL_PERIOD:
                    line = slapd_proc.stdout.readline()
                    slapd_output += line
                    _logging.debug('slapd: ' + line.rstrip('\n'))

                    if 'slapd starting' in line:
                        slapd_started = True
                        slapd_proc.stdout.close()
                        break

                # CAVEAT: sleep even after seeing ``slapd starting`` because on
                #     some systems that message is emitted slightly before
                #     slapd can actually accept connections
                _sleep(self._START_POLL_PERIOD)

            if pidfilepath:
                with open(pidfilepath, 'r') as pidfile:
                    pid = pidfile.read().strip()
            else:
                pid = slapd_proc.pid

            self._set_status('running', pid=pid)

        else:
            _os.execvp(slapd_args[0], slapd_args)

    def _start_nofork(self):
        self._start(fork=False)

    _PASSWORD_WITH_SCHEME_RE = \
        _re.compile(r'^\{(?P<scheme>\w+)\}(?P<value>.*)')

    _PIDFILE_STD_DIR = '/var/run'

    _START_POLL_PERIOD = 0.01
    """
    The period, in seconds, with which to poll the server for whether it has
    started.

    """

_services.Service.register_impl('openldap', OpenLdapService)


def _find_openldap_system_configdir():
    for dir_ in ('/etc/openldap', '/etc/ldap', '/usr/local/etc/openldap',
                 '/opt/local/etc/openldap'):
        if _os.path.isdir(dir_):
            return dir_

OPENLDAP_SYSTEM_CONFIG_DIR = _find_openldap_system_configdir()
