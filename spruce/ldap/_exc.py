"""Exceptions."""

__copyright__ = "Copyright (C) 2014 Ivan D Vasin"
__docformat__ = "restructuredtext"


class Error(RuntimeError):
    pass


class InvalidServiceOperation(Error):

    def __init__(self, service, operation, message=None, *args):
        super(InvalidServiceOperation, self).__init__(service, operation,
                                                      message, *args)
        self._message = message
        self._operation = operation
        self._service = service

    def __str__(self):
        message = 'cannot {} service {!r}'.format(self.operation, self.service)
        if self.message:
            message += ': ' + self.message
        return message

    @property
    def message(self):
        return self._message

    @property
    def operation(self):
        return self._operation

    @property
    def service(self):
        return self._service
