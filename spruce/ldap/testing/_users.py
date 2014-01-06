"""Test users."""

__copyright__ = "Copyright (C) 2014 Ivan D Vasin"
__docformat__ = "restructuredtext"

from .. import _users


ALICE = _users.InetOrgPerson(name='alice', displayname='Alice',
                             commonname='Alice Hacker', givenname='Alice',
                             surname='Hacker', password='xyzzy')

BOB = _users.InetOrgPerson(name='bob', displayname='Bob',
                           commonname='Bob Hacker', givenname='Bob',
                           surname='Hacker', password='chair')

CAROL = _users.InetOrgPerson(name='carol', displayname='Carol',
                             commonname='Carol Hacker', givenname='Carol',
                             surname='Hacker', password='love')

USERS = (ALICE, BOB, CAROL)

GROUPS = {'active': (ALICE, BOB), 'admins': (ALICE,), 'analysts': (BOB,),
          'authors': (BOB, CAROL)}
