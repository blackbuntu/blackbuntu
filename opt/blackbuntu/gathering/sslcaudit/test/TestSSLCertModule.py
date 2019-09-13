''' ----------------------------------------------------------------------
SSLCAUDIT - a tool for automating security audit of SSL clients
Released under terms of GPLv3, see COPYING.TXT
Copyright (C) 2012 Alexandre Bezroutchko abb@gremwell.com
---------------------------------------------------------------------- '''

import logging, unittest
from src.core.SSLCAuditCLI import SSLCAuditCLI

from src.core.ClientConnectionAuditEvent import ClientConnectionAuditResult
from src.modules.sslcert.ProfileFactory import DEFAULT_CN, SSLProfileSpec_SelfSigned, SSLProfileSpec_IMCA_Signed, SSLProfileSpec_Signed, IM_CA_FALSE_CN, IM_CA_TRUE_CN, IM_CA_NONE_CN, SSLProfileSpec_UserSupplied
from src.modules.sslcert.SSLServerHandler import     UNEXPECTED_EOF, ALERT_UNKNOWN_CA, ConnectedGotEOFBeforeTimeout, ConnectedGotRequest
from src.test import TestConfig
from src.test.SSLConnectionHammer import CNVerifyingSSLConnectionHammer
from src.test.TCPConnectionHammer import TCPConnectionHammer
from src.test.TestConfig import *
from src.test.ExternalCommandHammer import CurlHammer

LOCALHOST = 'localhost'
HAMMER_HELLO = 'hello'

def get_full_test_args(user_cn=TEST_USER_CN):
    return [
        '--user-cn', user_cn,
        '--user-cert', TEST_USER_CERT_FILE,
        '--server', TEST_SERVER,
        '--user-key', TEST_USER_KEY_FILE,
        '--user-ca-cert', TEST_USER_CA_CERT_FILE,
        '--user-ca-key', TEST_USER_CA_KEY_FILE
    ]


class ECCAR(object):
    def __init__(self, profile_spec, expected_res):
        self.profile_spec = profile_spec
        self.expected_result = expected_res

    def matches(self, actual_res):
        '''
        Given an actual audit result instance (ClientConnectionAuditResult) checks if it matches our expectations.
        '''
        if not (self.profile_spec == actual_res.profile.get_spec()):
            return False

        if self.expected_result == actual_res.res:
            return True
        else:
            return False

    def __str__(self):
        return "ECCAR(%s, %s)" % (self.profile_spec, self.expected_result)


class TestSSLCertModule(unittest.TestCase):
    '''
    Unittests for SSLCert.
    '''
    logger = logging.getLogger('TestSSLCertModule')

    def test_plain_tcp_client(self):
        # Plain TCP client causes unexpected UNEXPECTED_EOF.
        eccars = [
            # user-supplied certificate
            ECCAR(SSLProfileSpec_UserSupplied(TEST_USER_CERT_CN), UNEXPECTED_EOF),

            # self-signed certificates
            ECCAR(SSLProfileSpec_SelfSigned(DEFAULT_CN), UNEXPECTED_EOF),
            ECCAR(SSLProfileSpec_SelfSigned(TEST_USER_CN), UNEXPECTED_EOF),
            ECCAR(SSLProfileSpec_SelfSigned(TEST_SERVER_CN), UNEXPECTED_EOF),

            # signed by user-supplied certificate
            ECCAR(SSLProfileSpec_Signed(DEFAULT_CN, TEST_USER_CERT_CN), UNEXPECTED_EOF),
            ECCAR(SSLProfileSpec_Signed(TEST_USER_CN, TEST_USER_CERT_CN), UNEXPECTED_EOF),
            ECCAR(SSLProfileSpec_Signed(TEST_SERVER_CN, TEST_USER_CERT_CN), UNEXPECTED_EOF),

            # signed by user-supplied CA
            ECCAR(SSLProfileSpec_Signed(DEFAULT_CN, TEST_USER_CA_CN), UNEXPECTED_EOF),
            ECCAR(SSLProfileSpec_Signed(TEST_USER_CN, TEST_USER_CA_CN), UNEXPECTED_EOF),
            ECCAR(SSLProfileSpec_Signed(TEST_SERVER_CN, TEST_USER_CA_CN), UNEXPECTED_EOF),

            # default CN, signed by user-supplied CA, with an intermediate CA
            ECCAR(SSLProfileSpec_IMCA_Signed(DEFAULT_CN, IM_CA_NONE_CN, TEST_USER_CA_CN), UNEXPECTED_EOF),
            ECCAR(SSLProfileSpec_IMCA_Signed(DEFAULT_CN, IM_CA_FALSE_CN, TEST_USER_CA_CN), UNEXPECTED_EOF),
            ECCAR(SSLProfileSpec_IMCA_Signed(DEFAULT_CN, IM_CA_TRUE_CN, TEST_USER_CA_CN), UNEXPECTED_EOF),

            # user-supplied CN signed by user-supplied CA, with an intermediate CA
            ECCAR(SSLProfileSpec_IMCA_Signed(TEST_USER_CN, IM_CA_NONE_CN, TEST_USER_CA_CN), UNEXPECTED_EOF),
            ECCAR(SSLProfileSpec_IMCA_Signed(TEST_USER_CN, IM_CA_FALSE_CN, TEST_USER_CA_CN), UNEXPECTED_EOF),
            ECCAR(SSLProfileSpec_IMCA_Signed(TEST_USER_CN, IM_CA_TRUE_CN, TEST_USER_CA_CN), UNEXPECTED_EOF),

            # replica of server certificate signed by user-supplied CA, with an intermediate CA
            ECCAR(SSLProfileSpec_IMCA_Signed(TEST_SERVER_CN, IM_CA_NONE_CN, TEST_USER_CA_CN), UNEXPECTED_EOF),
            ECCAR(SSLProfileSpec_IMCA_Signed(TEST_SERVER_CN, IM_CA_FALSE_CN, TEST_USER_CA_CN), UNEXPECTED_EOF),
            ECCAR(SSLProfileSpec_IMCA_Signed(TEST_SERVER_CN, IM_CA_TRUE_CN, TEST_USER_CA_CN), UNEXPECTED_EOF)
        ]
        self._main_test(
            get_full_test_args(),
            TCPConnectionHammer(len(eccars)),
            eccars
        )

    def test_cn_verifying_client(self):
        # CN verifying client only cares about getting a correct CN
        eccars = [
            # user-supplied certificate
            ECCAR(SSLProfileSpec_UserSupplied(TEST_USER_CERT_CN), ConnectedGotEOFBeforeTimeout()),

            # self-signed certificates
            ECCAR(SSLProfileSpec_SelfSigned(DEFAULT_CN), ConnectedGotEOFBeforeTimeout()),
            ECCAR(SSLProfileSpec_SelfSigned(LOCALHOST), ConnectedGotRequest(HAMMER_HELLO)),
            ECCAR(SSLProfileSpec_SelfSigned(TEST_SERVER_CN), ConnectedGotEOFBeforeTimeout()),

            # signed by user-supplied certificate
            ECCAR(SSLProfileSpec_Signed(DEFAULT_CN, TEST_USER_CERT_CN), ConnectedGotEOFBeforeTimeout()),
            ECCAR(SSLProfileSpec_Signed(LOCALHOST, TEST_USER_CERT_CN), ConnectedGotRequest(HAMMER_HELLO)),
            ECCAR(SSLProfileSpec_Signed(TEST_SERVER_CN, TEST_USER_CERT_CN), ConnectedGotEOFBeforeTimeout()),

            # signed by user-supplied CA
            ECCAR(SSLProfileSpec_Signed(DEFAULT_CN, TEST_USER_CA_CN), ConnectedGotEOFBeforeTimeout()),
            ECCAR(SSLProfileSpec_Signed(LOCALHOST, TEST_USER_CA_CN), ConnectedGotRequest(HAMMER_HELLO)),
            ECCAR(SSLProfileSpec_Signed(TEST_SERVER_CN, TEST_USER_CA_CN), ConnectedGotEOFBeforeTimeout()),

            # default CN, signed by user-supplied CA, with an intermediate CA
            ECCAR(SSLProfileSpec_IMCA_Signed(DEFAULT_CN, IM_CA_NONE_CN, TEST_USER_CA_CN),
                ConnectedGotEOFBeforeTimeout()),
            ECCAR(SSLProfileSpec_IMCA_Signed(DEFAULT_CN, IM_CA_FALSE_CN, TEST_USER_CA_CN),
                ConnectedGotEOFBeforeTimeout()),
            ECCAR(SSLProfileSpec_IMCA_Signed(DEFAULT_CN, IM_CA_TRUE_CN, TEST_USER_CA_CN),
                ConnectedGotEOFBeforeTimeout()),

            # user-supplied CN signed by user-supplied CA, with an intermediate CA
            ECCAR(SSLProfileSpec_IMCA_Signed(LOCALHOST, IM_CA_NONE_CN, TEST_USER_CA_CN),
                ConnectedGotRequest(HAMMER_HELLO)),
            ECCAR(SSLProfileSpec_IMCA_Signed(LOCALHOST, IM_CA_FALSE_CN, TEST_USER_CA_CN),
                ConnectedGotRequest(HAMMER_HELLO)),
            ECCAR(SSLProfileSpec_IMCA_Signed(LOCALHOST, IM_CA_TRUE_CN, TEST_USER_CA_CN),
                ConnectedGotRequest(HAMMER_HELLO)),

            # replica of server certificate signed by user-supplied CA, with an intermediate CA
            ECCAR(SSLProfileSpec_IMCA_Signed(TEST_SERVER_CN, IM_CA_NONE_CN, TEST_USER_CA_CN),
                ConnectedGotEOFBeforeTimeout()),
            ECCAR(SSLProfileSpec_IMCA_Signed(TEST_SERVER_CN, IM_CA_FALSE_CN, TEST_USER_CA_CN),
                ConnectedGotEOFBeforeTimeout()),
            ECCAR(SSLProfileSpec_IMCA_Signed(TEST_SERVER_CN, IM_CA_TRUE_CN, TEST_USER_CA_CN),
                ConnectedGotEOFBeforeTimeout()),
            ]

        self._main_test(
            get_full_test_args(user_cn=LOCALHOST),
            CNVerifyingSSLConnectionHammer(len(eccars), HAMMER_HELLO),
            eccars)

    def test_curl(self):
        # curl does all the checks
        eccars = [
            # user-supplied certificate
            ECCAR(SSLProfileSpec_UserSupplied(TEST_USER_CERT_CN), ConnectedGotEOFBeforeTimeout()),

            # self-signed certificates
            ECCAR(SSLProfileSpec_SelfSigned(DEFAULT_CN), ALERT_UNKNOWN_CA),
            ECCAR(SSLProfileSpec_SelfSigned(LOCALHOST), ALERT_UNKNOWN_CA),
            ECCAR(SSLProfileSpec_SelfSigned(TEST_SERVER_CN), ALERT_UNKNOWN_CA),

            # signed by user-supplied certificate
            ECCAR(SSLProfileSpec_Signed(DEFAULT_CN, TEST_USER_CERT_CN), ALERT_UNKNOWN_CA),
            ECCAR(SSLProfileSpec_Signed(LOCALHOST, TEST_USER_CERT_CN), ALERT_UNKNOWN_CA),
            ECCAR(SSLProfileSpec_Signed(TEST_SERVER_CN, TEST_USER_CERT_CN), ALERT_UNKNOWN_CA),

            # signed by user-supplied CA
            ECCAR(SSLProfileSpec_Signed(DEFAULT_CN, TEST_USER_CA_CN), ConnectedGotEOFBeforeTimeout()),
            ECCAR(SSLProfileSpec_Signed(LOCALHOST, TEST_USER_CA_CN), ConnectedGotRequest()),
            ECCAR(SSLProfileSpec_Signed(TEST_SERVER_CN, TEST_USER_CA_CN), ConnectedGotEOFBeforeTimeout()),

            # default CN, signed by user-supplied CA, with an intermediate CA
            ECCAR(SSLProfileSpec_IMCA_Signed(DEFAULT_CN, IM_CA_NONE_CN, TEST_USER_CA_CN), ALERT_UNKNOWN_CA),
            ECCAR(SSLProfileSpec_IMCA_Signed(DEFAULT_CN, IM_CA_FALSE_CN, TEST_USER_CA_CN), ALERT_UNKNOWN_CA),
            ECCAR(SSLProfileSpec_IMCA_Signed(DEFAULT_CN, IM_CA_TRUE_CN, TEST_USER_CA_CN),
                ConnectedGotEOFBeforeTimeout()),

            # user-supplied CN signed by user-supplied CA, with an intermediate CA
            ECCAR(SSLProfileSpec_IMCA_Signed(LOCALHOST, IM_CA_NONE_CN, TEST_USER_CA_CN), ALERT_UNKNOWN_CA),
            ECCAR(SSLProfileSpec_IMCA_Signed(LOCALHOST, IM_CA_FALSE_CN, TEST_USER_CA_CN), ALERT_UNKNOWN_CA),
            ECCAR(SSLProfileSpec_IMCA_Signed(LOCALHOST, IM_CA_TRUE_CN, TEST_USER_CA_CN), ConnectedGotRequest()),

            # replica of server certificate signed by user-supplied CA, with an intermediate CA
            ECCAR(SSLProfileSpec_IMCA_Signed(TEST_SERVER_CN, IM_CA_NONE_CN, TEST_USER_CA_CN), ALERT_UNKNOWN_CA),
            ECCAR(SSLProfileSpec_IMCA_Signed(TEST_SERVER_CN, IM_CA_FALSE_CN, TEST_USER_CA_CN), ALERT_UNKNOWN_CA),
            ECCAR(SSLProfileSpec_IMCA_Signed(TEST_SERVER_CN, IM_CA_TRUE_CN, TEST_USER_CA_CN),
                ConnectedGotEOFBeforeTimeout()),
            ]

        self._main_test(
            get_full_test_args(user_cn=LOCALHOST),
            CurlHammer(len(eccars), TEST_USER_CA_CERT_FILE),
            eccars
        )

    def tearDown(self):
        if self.main != None:
            self.main.stop()

    def _main_test(self, main_args, hammer, expected_results):
        '''
        This is a main worker function. It allocates external resources and launches threads,
        to make sure they are freed this function was to be called exactly once per test method,
        to allow tearDown() method to cleanup properly.
        '''
        self._main_test_init(main_args, hammer)
        self._main_test_do(expected_results)

    def _main_test_init(self, args, hammer):
        # allocate port
        port = TestConfig.get_next_listener_port()

        # create main, the target of the test
        test_name = "%s %s" % (hammer, args)
        main_args = ['-l', '%s:%d' % (TestConfig.TEST_LISTENER_ADDR, port)]
        main_args.extend(args)
        self.main = SSLCAuditCLI(main_args)

        # collect classes of observed audit results
        self.actual_results = []
        self.orig_main__handle_result = self.main.handle_result

        def main__handle_result(res):
            self.orig_main__handle_result(res)
            if isinstance(res, ClientConnectionAuditResult):
                self.actual_results.append(res)
            else:
                pass # ignore events print res

        self.main.handle_result = main__handle_result

        self.hammer = hammer
        if self.hammer != None:
            self.hammer.set_peer((TestConfig.TEST_LISTENER_ADDR, port))

    def _main_test_do(self, expected_results):
        # run the server
        self.main.start()

        # start the hammer if any
        if self.hammer != None:
            self.hammer.start()

        # wait for main to finish its job
        self.main.join(timeout=TestConfig.TEST_MAIN_JOIN_TIMEOUT)
        # on timeout throws exception, which we let propagate after we shut the hammer and the main thread

        self.assertFalse(self.main.is_alive(), 'main thread is still alive')

        # stop the hammer if any
        if self.hammer != None:    self.hammer.stop()

        # stop the server
        self.main.stop()

        # check if the actual results match expected ones
        if len(expected_results) != len(self.actual_results):
            mismatch = True
            print "! length mismatch len(er)=%d, len(ar)=%d" % (len(expected_results), len(self.actual_results))
            for er in expected_results: print "er=%s" % er
            for ar in self.actual_results: print "ar=%s" % ar
        else:
            mismatch = False
            for i in range(len(expected_results)):
                er = expected_results[i]
                ar = self.actual_results[i]
                if not er.matches(ar):
                    print "! mismatch\n\ter=%s\n\tar=%s" % (er, ar)
                    mismatch = True
        self.assertFalse(mismatch)

if __name__ == '__main__':
    unittest.main()
