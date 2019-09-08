''' ----------------------------------------------------------------------
SSLCAUDIT - a tool for automating security audit of SSL clients
Released under terms of GPLv3, see COPYING.TXT
Copyright (C) 2012 Alexandre Bezroutchko abb@gremwell.com
---------------------------------------------------------------------- '''

class ClientConnectionAuditEvent(object):
    '''
    This is a base class for events produced while auditing client connections.
    '''
    def __init__(self, conn, profile):
        self.profile = profile
        self.conn = conn

    def __eq__(self, other):
        return (self.__class__ == other.__class__) and (self.__dict__ == other.__dict__)


class ClientConnectionAuditResult(ClientConnectionAuditEvent):
    '''
    This class contains audit results returned by handle() method of subclasses of BaseServerHandler. It
    contains the results of the audit of a single connection.
    '''

    def __init__(self, conn, profile, res):
        ClientConnectionAuditEvent.__init__(self, conn, profile)
        self.res = res

    def __str__(self):
        return ' CCAR(%s[%s], %s)' % (self.profile, self.profile.certnkey.cert_filename, self.res)

class ClientAuditStartEvent(ClientConnectionAuditEvent):
    '''
    This event is generated by ClientHandler on very first connection.
    '''
    pass


class ClientAuditEndEvent(ClientConnectionAuditEvent):
    '''
    This event is generated by ClientHandler after very last connection.
    '''
    pass

class ClientAuditResult(object):
    '''
    This event is generated by ClientHandler after very last connection, after ClientAuditEndEvent. It contains results
    produced by handle() methods of all client connection auditors, for a single client.
    '''

    def __init__(self, client_id):
        self.client_id = client_id
        self.results = []

    def add(self, res):
        self.results.append(res)
