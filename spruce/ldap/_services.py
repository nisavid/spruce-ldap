"""LDAP services core."""

__copyright__ = "Copyright (C) 2014 Ivan D Vasin"
__docformat__ = "restructuredtext"

import abc as _abc
import os as _os
import re as _re
import signal as _signal

import ldap as _ldap
import psutil as _ps
from spruce.lang import bool as _bool, enum as _enum, int as _int

from . import _exc


class Service(object):

    """An LDAP service.

    A :class:`!Service` provides an interface to an underlying service
    implementation.

    This class provides an entry point to any server implementation that is
    available in the current environment.  It exposes the interface of the
    chosen implementation, which is a :class:`ServiceImpl` subclass.

    To instantiate a service using any available implementation, omit
    *impl*.  To instantiate a service using a particular implementation,
    provide a registered *impl* name.  To register a new implementation, use
    :meth:`register_impl`.

    These implementations are available by default if their corresponding
    dependencies are met:

    ============ ================= =================================================
    Name         Class             Dependencies
    ============ ================= =================================================
    ``openldap`` |OpenLdapService| OpenLDAP's :command:`slapd` in the :envvar:`!PATH`
    ============ ================= =================================================

    .. |OpenLdapService| replace::
        :class:`~spruce.ldap.openldap._services.OpenLdapService`

    .. seealso:: :class:`ServiceImpl`

    :param impl:
        The name of a :class:`!Service` implementation.
    :type impl: :obj:`str` or null

    """

    def __init__(self, uris, configloc, impl=None, pid=None, stop_on_del=True,
                 **kwargs):
        self.__dict__['_impl'] = \
            self.impl_class(impl)(uris=uris, configloc=configloc, pid=pid,
                                  stop_on_del=stop_on_del, **kwargs)

    def __getattr__(self, name):
        try:
            return getattr(self.impl, name)
        except AttributeError as exc:
            try:
                return object.__getattr__(self, name)
            except AttributeError:
                raise exc

    def __setattr__(self, name, value):
        if hasattr(self.impl, name):
            setattr(self.impl, name, value)
        else:
            object.__setattr__(self, name, value)

    @classmethod
    def create_basic(cls, uris, configloc, schemas, modules, config_password,
                     dbtype, dbdir, suffix, root_dn, root_password, impl=None,
                     authz_map=None, access=(), index=(), pidfile=None):
        return cls.impl_class(impl)\
                  .create_basic(uris=uris,
                                configloc=configloc,
                                schemas=schemas,
                                modules=modules,
                                config_password=config_password,
                                dbtype=dbtype,
                                dbdir=dbdir,
                                suffix=suffix,
                                root_dn=root_dn,
                                root_password=root_password,
                                authz_map=authz_map,
                                access=access,
                                index=index,
                                pidfile=pidfile)

    @property
    def impl(self):
        """This LDAP service's implementation.

        :type: :class:`ServiceImpl`

        """
        return self._impl

    @classmethod
    def impl_class(cls, name=None):
        if name is None:
            try:
                name = cls._impls.keys()[0]
            except IndexError:
                raise RuntimeError('cannot find any implementations of {}.{}'
                                    .format(cls.__module__, cls.__name__))
        return cls._impls[name]

    @classmethod
    def register_impl(cls, name, impl):
        """Register an LDAP service implementation.

        :param str name:
            The implementation's name.

        :param impl:
            The implementation.
        :type impl: :class:`ServiceImpl`

        """
        cls._impls[name] = impl

    _impls = {}


class ServiceImpl(object):

    """A :class:`Service` implementation.

    .. note:: **TODO:**
        encapsulate the components that are common to this and
        :class:`bedframe.ServiceImpl <bedframe._services.ServiceImpl>`

    """

    __metaclass__ = _abc.ABCMeta

    def __init__(self, uris, configloc, pid=None, stop_on_del=True):

        self._configloc = configloc
        self.stop_on_del = stop_on_del
        self._uris = tuple(uris)

        if pid is not None:
            self._set_status('running', pid=pid)
        else:
            self._set_status('stopped')

    def __del__(self):

        try:
            stop = self.stop_on_del and self.status == 'running'
        except AttributeError:
            stop = False

        if stop:
            self.stop()

    def client(self):

        chosen_uri = None
        for uri in self.uris:
            if uri.lower().startswith('ldapi:'):
                chosen_uri = uri
                break
        if not chosen_uri:
            chosen_uri = self.uris[0]

        return _ldap.initialize(chosen_uri)

    @property
    def configloc(self):
        return self._configloc

    @classmethod
    @_abc.abstractmethod
    def create_basic(cls, uris, configloc, schemas, modules, config_password,
                     dbtype, dbdir, suffix, root_dn, root_password,
                     authz_map=None, access=(), index=(), pidfile=None):
        pass

    @property
    def pid(self):
        return self._pid

    def start(self, fork=False):

        if self.status == 'running':
            raise _exc.InvalidServiceOperation\
                   (self, 'start', 'the service is already running')

        self._start(fork=fork)

    @property
    def status(self):
        self._probe_status()
        return self._status

    def stop(self):

        if self.status != 'running':
            raise _exc.InvalidServiceOperation(self, 'stop',
                                               'the service is not running')

        try:
            _os.kill(self.pid, _signal.SIGTERM)
        except OSError as exc:
            if exc.errno == _os.errno.ESRCH:
                self._set_status('gone')
                raise _exc.InvalidServiceOperation\
                       (self, 'stop',
                        'the service went away before it could be stopped')
            else:
                raise
        else:
            self._slapd_proc.poll()
            _os.waitpid(self.pid, 0)
            self._set_status('stopped')

    @property
    def stop_on_del(self):
        return self._stop_on_del

    @stop_on_del.setter
    def stop_on_del(self, value):
        self._stop_on_del = _bool(value)

    @property
    def uris(self):
        return self._uris

    def _probe_status(self):
        if self._status == 'running':
            gone = False
            if _ps.pid_exists(self.pid):
                if _ps.Process(self.pid).status == _ps.STATUS_ZOMBIE:
                    gone = True
                    _os.waitpid(self.pid, 0)
            else:
                gone = True
            if gone:
                self._set_status('gone')

    def _set_status(self, status, pid=None):

        if status == 'running' and pid is None:
            raise ValueError('missing arg pid: required by status {!r}'
                              .format(status))

        if status == 'running':
            pid = _int(pid)
        else:
            pid = None

        self._pid = pid
        self._status = status

        if pid is not None:
            self._probe_status()

    def _start(self, fork=False):

        if fork:
            pid = _os.fork()
            if pid != 0:
                self._set_status('running', pid=pid)
                return pid

        self._start_nofork()
        self._set_status('running', pid=_os.getpid())

    @_abc.abstractmethod
    def _start_nofork(self):
        pass

    _SUFFIX_ORG_DN_RE = _re.compile(r'^dc=(?P<org>[^,]*),dc=(?P<tld>[^,]*)$')


ServiceStatus = _enum('LDAP service status', ('stopped', 'running', 'gone'))
