"""Services testing."""

__copyright__ = "Copyright (C) 2014 Ivan D Vasin"
__docformat__ = "restructuredtext"

import abc as _abc
import os as _os
import shutil as _sh
from tempfile import mkdtemp as _mkdtemp
import unittest as _unittest

import spruce.ldap as _ldap
import spruce.ldap.openldap as _openldap

from . import _users as _test_users


class LdapTestService(_ldap.Service):

    def __init__(self,
                 implname='openldap',
                 uris=None,
                 rootdir=None,
                 configloc=None,
                 schemas=None,
                 modules=('back_hdb.la',),
                 config_password='admin',
                 dbtype='hdb',
                 dbdir=None,
                 domain='example.net',
                 suffix=None,
                 root_dn=None,
                 root_password='admin',
                 authz_map=None,
                 users_dn=None,
                 users=None,
                 groups_dn=None,
                 groups=None,
                 access=None,
                 index=('uid eq,pres,sub',),
                 pidfile=None):

        self.__dict__['_impl'] = None

        if rootdir is None:
            if configloc is None or dbdir is None or pidfile is None \
                   or uris is None:
                rootdir = self._create_rootdir()
        self.__dict__['_rootdir'] = rootdir

        self.__dict__['_domain'] = domain
        self.__dict__['_suffix'] = suffix if suffix is not None \
                              else ','.join('dc={}'.format(dc)
                                            for dc in self.domain.split('.'))
        self.__dict__['_groups_dn'] = groups_dn if groups_dn is not None \
                                      else 'ou=groups,{}'.format(self.suffix)
        self.__dict__['_users_dn'] = users_dn if users_dn is not None \
                                     else 'ou=users,{}'.format(self.suffix)

        self.__dict__['_access'] = \
            access if access is not None \
                   else ('to attrs=userPassword'
                          ' by self write by anonymous auth by * none',
                         'to dn.base="" by * read',
                         'to *'
                          ' by self write'
                          ' by group="cn=admins,{}" read'
                          ' by anonymous auth'
                          ' by * none'
                          .format(self.groups_dn))
        self.__dict__['_authz_map'] = \
            authz_map if authz_map is not None \
                      else {r'uid=([^,]*),cn=[^,]*,cn=auth':
                                'uid=$1,{}'.format(self.users_dn),
                            (r'uid=([^,]*),cn=[^,]*,cn={},cn=auth'
                              .format(self.domain)):
                                'uid=$1,{}'.format(self.users_dn),
                            }
        self.__dict__['_config_password'] = config_password
        configloc = configloc if configloc is not None \
                              else _os.path.join(self.rootdir, 'slapd.d')
        self.__dict__['_dbdir'] = dbdir if dbdir is not None \
                                        else _os.path.join(self.rootdir, 'db')
        self.__dict__['_dbtype'] = dbtype
        self.__dict__['_groups'] = groups if groups is not None \
                                          else _test_users.GROUPS
        self.__dict__['_index'] = index
        self.__dict__['_implname'] = implname
        self.__dict__['_modules'] = modules
        self.__dict__['_pidfile'] = \
            pidfile if pidfile is not None \
                    else _os.path.join(self.rootdir, 'slapd.pid')
        self.__dict__['_root_dn'] = \
            root_dn if root_dn is not None \
                    else 'cn=admin,{}'.format(self.suffix)
        self.__dict__['_root_password'] = root_password
        self.__dict__['_schemas'] = \
            schemas if schemas is not None \
                    else [_os.path.join(_openldap.OPENLDAP_SYSTEM_CONFIG_DIR,
                                        'schema', schema + '.schema')
                          for schema in ('core', 'cosine', 'inetorgperson')]
        uris = uris if uris is not None \
                    else ('ldapi://{}/'.format(_os.path.join(self.rootdir,
                                                             'ldapi')
                                                .replace('/', '%2F')),)
        self.__dict__['_users'] = users if users is not None \
                                        else _test_users.USERS

        self.create_basic(impl=self.implname,
                          uris=uris,
                          configloc=configloc,
                          schemas=self.schemas,
                          modules=self.modules,
                          config_password=self.config_password,
                          dbtype=self.dbtype,
                          dbdir=self.dbdir,
                          suffix=self.suffix,
                          root_dn=self.root_dn,
                          root_password=self.root_password,
                          authz_map=self.authz_map,
                          access=self.access,
                          index=self.index,
                          pidfile=self.pidfile)

        super(LdapTestService, self)\
         .__init__(impl=self.implname, uris=uris, configloc=configloc,
                   stop_on_del=True)

        self.start(fork=True)
        self._setup_users()
        self.stop()

    def __del__(self):
        self._destroy_rootdir()

    @property
    def access(self):
        return self._access

    @property
    def authz_map(self):
        return self._authz_map

    @property
    def config_password(self):
        return self._config_password

    @property
    def dbdir(self):
        return self._dbdir

    @property
    def dbtype(self):
        return self._dbtype

    @property
    def domain(self):
        return self._domain

    @property
    def groups(self):
        return self._groups

    @property
    def groups_dn(self):
        return self._groups_dn

    @property
    def implname(self):
        return self._implname

    @property
    def index(self):
        return self._index

    @property
    def modules(self):
        return self._modules

    @property
    def pidfile(self):
        return self._pidfile

    @property
    def root_dn(self):
        return self._root_dn

    @property
    def root_password(self):
        return self._root_password

    @property
    def rootdir(self):
        return self._rootdir

    @property
    def schemas(self):
        return self._schemas

    @property
    def suffix(self):
        return self._suffix

    @property
    def users(self):
        return self._users

    @property
    def users_dn(self):
        return self._users_dn

    def _create_rootdir(self):
        path = _mkdtemp(prefix='ldaptest-slapd-')
        _os.mkdir(_os.path.join(path, 'db'))
        _os.mkdir(_os.path.join(path, 'slapd.d'))
        return path

    def _destroy_rootdir(self):
        if self.rootdir is not None:
            _sh.rmtree(self.rootdir)

    def _setup_users(self):

        ldap = self.client()
        ldap.simple_bind_s(self.root_dn, self.root_password)

        ldap.add_s(self.users_dn,
                   (('objectClass', 'organizationalUnit'),
                    ('ou', 'users')))
        ldap.add_s(self.groups_dn,
                   (('objectClass', 'organizationalUnit'),
                    ('ou', 'groups')))

        for user in self.users:
            ldap.add_s('uid={},{}'.format(user.name, self.users_dn),
                       (('objectClass', 'inetOrgPerson'),
                        ('uid', user.name),
                        ('displayName', user.displayname),
                        ('cn', user.commonname),
                        ('givenName', user.givenname),
                        ('sn', user.surname),
                        ('userPassword', user.password),
                        ))

        for group, group_users in self.groups.items():
            ldap.add_s('cn={},{}'.format(group, self.groups_dn),
                       (('objectClass', 'groupOfNames'),
                        ('cn', group),
                        ('member',
                         ['uid={},{}'.format(user.name, self.users_dn)
                          for user in group_users])))


class LdapServiceTestCase(_unittest.TestCase):

    """LDAP service tests."""

    __metaclass__ = _abc.ABCMeta

    def __init__(self, *args, **kwargs):
        super(LdapServiceTestCase, self).__init__(*args, **kwargs)
        self._ldapservice = None

    @property
    def ldapservice(self):
        return self._ldapservice

    @property
    def ldapservice_configloc(self):
        return self.ldapservice.configloc

    @property
    def ldapservice_pid(self):
        return self.ldapservice.pid

    @property
    def ldapservice_uris(self):
        return self.ldapservice.uris

    def setUp(self):
        self._setup_ldapservice()
        super(LdapServiceTestCase, self).setUp()

    def tearDown(self):
        super(LdapServiceTestCase, self).tearDown()
        self._teardown_ldapservice()

    @_abc.abstractmethod
    def _create_ldapservice(self):
        pass

    def _setup_ldapservice(self):
        self._ldapservice = self._create_ldapservice()
        self._start_ldapservice()

    @_abc.abstractmethod
    def _start_ldapservice(self):
        pass

    @_abc.abstractmethod
    def _teardown_ldapservice(self):
        pass


class LdapTestServiceTestCase(LdapServiceTestCase):

    @property
    def ldapservice_config_password(self):
        return self.ldapservice.config_password

    @property
    def ldapservice_configloc(self):
        return self.ldapservice.configloc

    @property
    def ldapservice_dbdir(self):
        return self.ldapservice.dbdir

    @property
    def ldapservice_dbtype(self):
        return self.ldapservice.dbtype

    @property
    def ldapservice_domain(self):
        return self.ldapservice.domain

    @property
    def ldapservice_groups(self):
        return self.ldapservice.groups

    @property
    def ldapservice_groups_dn(self):
        return self.ldapservice.groups_dn

    @property
    def ldapservice_implname(self):
        return self.ldapservice.implname

    @property
    def ldapservice_index(self):
        return self.ldapservice.index

    @property
    def ldapservice_modules(self):
        return self.ldapservice.modules

    @property
    def ldapservice_pidfile(self):
        return self.ldapservice.pidfile

    @property
    def ldapservice_root_dn(self):
        return self.ldapservice.root_dn

    @property
    def ldapservice_root_password(self):
        return self.ldapservice.root_password

    @property
    def ldapservice_rootdir(self):
        return self.ldapservice.rootdir

    @property
    def ldapservice_schemas(self):
        return self.ldapservice.schemas

    @property
    def ldapservice_suffix(self):
        return self.ldapservice.suffix

    @property
    def ldapservice_uris(self):
        return self.ldapservice.uris

    @property
    def ldapservice_users(self):
        return self.ldapservice.users

    @property
    def ldapservice_users_dn(self):
        return self.ldapservice.users_dn

    def _create_ldapservice(self):
        return LdapTestService()

    def _start_ldapservice(self):
        self.ldapservice.start(fork=True)

    def _teardown_ldapservice(self):
        self.ldapservice.stop()


class LdapExternalServiceTestCase(LdapServiceTestCase):

    __metaclass__ = _abc.ABCMeta

    def _start_ldapservice(self):
        pass

    def _teardown_ldapservice(self):
        pass
