"""Users."""

__copyright__ = "Copyright (C) 2014 Ivan D Vasin"
__docformat__ = "restructuredtext"

from collections import namedtuple as _namedtuple


class InetOrgPerson(_namedtuple('InetOrgPerson',
                                ('commonname', 'displayname', 'givenname',
                                 'name', 'password', 'surname'))):

    def __repr__(self):
        return '{}(name={}, displayname={}, commonname={}, givenname={},'\
                ' surname={}, password={})'\
                .format(self.__class__.__name__, self.name, self.displayname,
                        self.commonname, self.givenname, self.surname,
                        self.password)

    def __str__(self):
        return self.name
