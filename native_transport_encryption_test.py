import logging
import ssl

import pytest
from cassandra import ConsistencyLevel
from cassandra.cluster import NoHostAvailable

from dtest import Tester, create_cf, create_ks
from tools import sslkeygen
from tools.data import putget

since = pytest.mark.since
logger = logging.getLogger(__name__)


class TestNativeTransportEncryption(Tester):
    """
    * Native transport integration tests designed to exercise different SSL options.
    *
    * Each test case launch the server with some defined client_encryption_options and
    * associated keys/certificates.
    * Further, each test case (except cleartext test case) will create 3 different
    * client side SSL keys/certificates:
    * - The first is valid - signed by a CA trusted by the server, and SAN is matching
    *   the client.
    * - The second is invalid - signed, but not by a a CA trusted by the server.
    * - The second is invalid - SAN is not matching actual client IP
    * A set of client connection attempts are then performed to verify expected behavior
    * using these keys.
    * The connection attempt will succeed or fail depending on how strict the SSL
    * configuration is on client side and on server side.
    """

    def test_accept_cleartext(self):
        """
        * Launch server with client encryption disabled.
        *
        * Non-SSL client connections will succeed.
        * All SSL client connections will fail.
        """

        cluster = self.cluster
        credClient = sslkeygen.generate_credentials("127.0.0.1")

        cluster.set_configuration_options({
            'client_encryption_options': {
                'enabled': False
            }
        })

        cluster.populate(1)
        node1 = cluster.nodelist()[0]
        cluster.start()

        self._connect_without_ssl(cluster, node1, expectSuccess=True)

        self._connect_with_ssl(cluster, node1, expectSuccess=False)

        self._connect_with_ssl_and_validate(
            cluster, node1, credClient.cacert, expectSuccess=False)
        self._connect_with_ssl_key(
            cluster, node1, credClient.cert, credClient.key, expectSuccess=False)
        self._connect_with_ssl_key_and_validate(
            cluster, node1, credClient.cert, credClient.key, credClient.cacert, expectSuccess=False)

        cluster.stop()

    @since('3.0')
    def test_accept_ssl_optional(self):
        """
        * Launch server with client encryption enabled.
        * - SSL optional
        * - No client verification/validation.
        *
        * Non-SSL client connections will succeed.
        * SSL client connections will fail if server certificate is not trusted by client CA.
        * All other SSL client connections will succeed.
        @since 3.0
        """

        cluster = self.cluster
        credServer = sslkeygen.generate_credentials("127.0.0.1")
        credCorrectClient = sslkeygen.generate_credentials("127.0.0.1", credServer.cakeystore, credServer.cacert)
        credOtherCaClient = sslkeygen.generate_credentials("127.0.0.1")
        credWrongIpClient = sslkeygen.generate_credentials("127.0.0.10", credServer.cakeystore, credServer.cacert)

        cluster.set_configuration_options({
            'client_encryption_options': {
                'enabled': True,
                'optional': True,
                'keystore': credServer.keystore,
                'keystore_password': 'cassandra'
            }
        })

        cluster.populate(1)
        node1 = cluster.nodelist()[0]
        self.fixture_dtest_setup.allow_log_errors = True
        cluster.start()

        self._connect_without_ssl(cluster, node1, expectSuccess=True)

        self._connect_with_ssl(cluster, node1, expectSuccess=True)

        self._connect_with_ssl_and_validate(
            cluster, node1, credCorrectClient.cacert, expectSuccess=True)
        self._connect_with_ssl_key(
            cluster, node1, credCorrectClient.cert, credCorrectClient.key, expectSuccess=True)
        self._connect_with_ssl_key_and_validate(
            cluster, node1, credCorrectClient.cert, credCorrectClient.key, credCorrectClient.cacert, expectSuccess=True)

        self._connect_with_ssl_and_validate(
            cluster, node1, credOtherCaClient.cacert, expectSuccess=False)
        self._connect_with_ssl_key(
            cluster, node1, credOtherCaClient.cert, credOtherCaClient.key, expectSuccess=True)
        self._connect_with_ssl_key_and_validate(
            cluster, node1, credOtherCaClient.cert, credOtherCaClient.key, credOtherCaClient.cacert, expectSuccess=False)

        self._connect_with_ssl_and_validate(
            cluster, node1, credWrongIpClient.cacert, expectSuccess=True)
        self._connect_with_ssl_key(
            cluster, node1, credWrongIpClient.cert, credWrongIpClient.key, expectSuccess=True)
        self._connect_with_ssl_key_and_validate(
            cluster, node1, credWrongIpClient.cert, credWrongIpClient.key, credWrongIpClient.cacert, expectSuccess=True)

        cluster.stop()

    def test_accept_ssl(self):
        """
        * Launch server with client encryption enabled.
        * - SSL mandatory
        * - No client verification/validation.
        *
        * Non-SSL client connections will fail.
        * SSL client connections will fail if server certificate is not trusted by client CA.
        * All other SSL client connections will succeed.
        """

        cluster = self.cluster
        credServer = sslkeygen.generate_credentials("127.0.0.1")
        credCorrectClient = sslkeygen.generate_credentials("127.0.0.1", credServer.cakeystore, credServer.cacert)
        credOtherCaClient = sslkeygen.generate_credentials("127.0.0.1")
        credWrongIpClient = sslkeygen.generate_credentials("127.0.0.10", credServer.cakeystore, credServer.cacert)

        cluster.set_configuration_options({
            'client_encryption_options': {
                'enabled': True,
                'optional': False,
                'keystore': credServer.keystore,
                'keystore_password': 'cassandra'
            }
        })

        cluster.populate(1)
        node1 = cluster.nodelist()[0]
        self.fixture_dtest_setup.allow_log_errors = True
        cluster.start()

        self._connect_without_ssl(cluster, node1, expectSuccess=False)

        self._connect_with_ssl(cluster, node1, expectSuccess=True)

        self._connect_with_ssl_and_validate(
            cluster, node1, credCorrectClient.cacert, expectSuccess=True)
        self._connect_with_ssl_key(
            cluster, node1, credCorrectClient.cert, credCorrectClient.key, expectSuccess=True)
        self._connect_with_ssl_key_and_validate(
            cluster, node1, credCorrectClient.cert, credCorrectClient.key, credCorrectClient.cacert, expectSuccess=True)

        self._connect_with_ssl_and_validate(
            cluster, node1, credOtherCaClient.cacert, expectSuccess=False)
        self._connect_with_ssl_key(
            cluster, node1, credOtherCaClient.cert, credOtherCaClient.key, expectSuccess=True)
        self._connect_with_ssl_key_and_validate(
            cluster, node1, credOtherCaClient.cert, credOtherCaClient.key, credOtherCaClient.cacert, expectSuccess=False)

        self._connect_with_ssl_and_validate(
            cluster, node1, credWrongIpClient.cacert, expectSuccess=True)
        self._connect_with_ssl_key(
            cluster, node1, credWrongIpClient.cert, credWrongIpClient.key, expectSuccess=True)
        self._connect_with_ssl_key_and_validate(
            cluster, node1, credWrongIpClient.cert, credWrongIpClient.key, credWrongIpClient.cacert, expectSuccess=True)

        cluster.stop()

    def test_accept_ssl_auth_client(self):
        """
        * Launch server with client encryption enabled.
        * - SSL mandatory
        * - Verify client certificate.
        * - No client hostname validation.
        *
        * Non-SSL client connections will fail.
        * SSL client connections will fail if server certificate is not trusted by client CA.
        * SSL client connections will fail if client certificate is not trusted by server CA.
        * SSL client connections will fail if client does not offer certificate to server.
        * All other SSL client connections will succeed.
        """

        cluster = self.cluster
        credServer = sslkeygen.generate_credentials("127.0.0.1")
        credCorrectClient = sslkeygen.generate_credentials("127.0.0.1", credServer.cakeystore, credServer.cacert)
        credOtherCaClient = sslkeygen.generate_credentials("127.0.0.1")
        credWrongIpClient = sslkeygen.generate_credentials("127.0.0.10", credServer.cakeystore, credServer.cacert)

        cluster.set_configuration_options({
            'client_encryption_options': {
                'enabled': True,
                'optional': False,
                'keystore': credServer.keystore,
                'keystore_password': 'cassandra',
                'require_client_auth': True,
                'truststore': credServer.cakeystore,
                'truststore_password': 'cassandra'
            }
        })

        cluster.populate(1)
        node1 = cluster.nodelist()[0]
        self.fixture_dtest_setup.allow_log_errors = True
        cluster.start()

        self._connect_without_ssl(cluster, node1, expectSuccess=False)

        self._connect_with_ssl(cluster, node1, expectSuccess=False)

        self._connect_with_ssl_and_validate(
            cluster, node1, credCorrectClient.cacert, expectSuccess=False)
        self._connect_with_ssl_key(
            cluster, node1, credCorrectClient.cert, credCorrectClient.key, expectSuccess=True)
        self._connect_with_ssl_key_and_validate(
            cluster, node1, credCorrectClient.cert, credCorrectClient.key, credCorrectClient.cacert, expectSuccess=True)

        self._connect_with_ssl_and_validate(
            cluster, node1, credOtherCaClient.cacert, expectSuccess=False)
        self._connect_with_ssl_key(
            cluster, node1, credOtherCaClient.cert, credOtherCaClient.key, expectSuccess=False)
        self._connect_with_ssl_key_and_validate(
            cluster, node1, credOtherCaClient.cert, credOtherCaClient.key, credOtherCaClient.cacert, expectSuccess=False)

        self._connect_with_ssl_and_validate(
            cluster, node1, credWrongIpClient.cacert, expectSuccess=False)
        self._connect_with_ssl_key(
            cluster, node1, credWrongIpClient.cert, credWrongIpClient.key, expectSuccess=True)
        self._connect_with_ssl_key_and_validate(
            cluster, node1, credWrongIpClient.cert, credWrongIpClient.key, credWrongIpClient.cacert, expectSuccess=True)

        cluster.stop()

    @since('4.0')
    def test_accept_ssl_verify_client(self):
        """
        * Launch server with client encryption enabled.
        * - SSL mandatory
        * - Verify client certificate.
        * - Validate client hostname.
        *
        * Non-SSL client connections will fail.
        * SSL client connections will fail if server certificate is not trusted by client CA.
        * SSL client connections will fail if client certificate is not trusted by server CA.
        * SSL client connections will fail if client does not offer certificate to server.
        * SSL client connections will fail if client IP does not match certificate SAN.
        * All other SSL client connections will succeed.
        @jira_ticket CASSANDRA-13404
        @since 4.0
        """

        cluster = self.cluster
        credServer = sslkeygen.generate_credentials("127.0.0.1")
        credCorrectClient = sslkeygen.generate_credentials("127.0.0.1", credServer.cakeystore, credServer.cacert)
        credOtherCaClient = sslkeygen.generate_credentials("127.0.0.1")
        credWrongIpClient = sslkeygen.generate_credentials("127.0.0.10", credServer.cakeystore, credServer.cacert)

        cluster.set_configuration_options({
            'client_encryption_options': {
                'enabled': True,
                'optional': False,
                'keystore': credServer.keystore,
                'keystore_password': 'cassandra',
                'require_client_auth': True,
                'require_endpoint_verification': True,
                'truststore': credServer.cakeystore,
                'truststore_password': 'cassandra'
            }
        })

        cluster.populate(1)
        node1 = cluster.nodelist()[0]
        self.fixture_dtest_setup.allow_log_errors = True
        cluster.start()

        self._connect_without_ssl(cluster, node1, expectSuccess=False)

        self._connect_with_ssl(cluster, node1, expectSuccess=False)

        self._connect_with_ssl_and_validate(
            cluster, node1, credCorrectClient.cacert, expectSuccess=False)
        self._connect_with_ssl_key(
            cluster, node1, credCorrectClient.cert, credCorrectClient.key, expectSuccess=True)
        self._connect_with_ssl_key_and_validate(
            cluster, node1, credCorrectClient.cert, credCorrectClient.key, credCorrectClient.cacert, expectSuccess=True)

        self._connect_with_ssl_and_validate(
            cluster, node1, credOtherCaClient.cacert, expectSuccess=False)
        self._connect_with_ssl_key(
            cluster, node1, credOtherCaClient.cert, credOtherCaClient.key, expectSuccess=False)
        self._connect_with_ssl_key_and_validate(
            cluster, node1, credOtherCaClient.cert, credOtherCaClient.key, credOtherCaClient.cacert, expectSuccess=False)

        self._connect_with_ssl_and_validate(
            cluster, node1, credWrongIpClient.cacert, expectSuccess=False)
        self._connect_with_ssl_key(
            cluster, node1, credWrongIpClient.cert, credWrongIpClient.key, expectSuccess=False)
        self._connect_with_ssl_key_and_validate(
            cluster, node1, credWrongIpClient.cert, credWrongIpClient.key, credWrongIpClient.cacert, expectSuccess=False)

        cluster.stop()

    def _connect_without_ssl(self, cluster, node, expectSuccess=True):
        try:
            session = self.patient_cql_connection(node, timeout=5)
            if not expectSuccess:
                pytest.fail('Should not be able to connect cleartext client')
            self._putget(cluster, session)
        except NoHostAvailable:
            if expectSuccess:
                pytest.fail('Should be able to connect with cleartext client')

    def _connect_with_ssl(self, cluster, node, expectSuccess=True):
        try:
            session = self.patient_cql_connection(node, timeout=5, ssl_opts={
                                                  'cert_reqs': ssl.CERT_NONE})
            if not expectSuccess:
                pytest.fail('Should not be able to connect with SSL client')
            self._putget(cluster, session)
        except NoHostAvailable:
            if expectSuccess:
                pytest.fail('Should be able to connect with SSL client')

    def _connect_with_ssl_and_validate(
            self, cluster, node, cacert, expectSuccess=True):
        try:
            session = self.patient_cql_connection(node, timeout=5, ssl_opts={
                                                  'cert_reqs': ssl.CERT_REQUIRED, 'ca_certs': cacert})
            if not expectSuccess:
                pytest.fail('Should not be able to connect with SSL client using server validation')
            self._putget(cluster, session)
        except NoHostAvailable:
            if expectSuccess:
                pytest.fail('Should be able to connect with SSL client using server validation')

    def _connect_with_ssl_key(
            self, cluster, node, cert, key, expectSuccess=True):
        try:
            session = self.patient_cql_connection(node, timeout=5, ssl_opts={
                                                  'certfile': cert, 'keyfile': key, 'cert_reqs': ssl.CERT_NONE})
            if not expectSuccess:
                pytest.fail('Should not be able to connect with SSL client when providing certificate and key')
            self._putget(cluster, session)
        except NoHostAvailable:
            if expectSuccess:
                pytest.fail('Should be able to connect with SSL client when providing certificate and key')

    def _connect_with_ssl_key_and_validate(
            self, cluster, node, cert, key, cacert, expectSuccess=True):
        try:
            session = self.patient_cql_connection(node, timeout=5, ssl_opts={
                                                  'certfile': cert, 'keyfile': key, 'cert_reqs': ssl.CERT_REQUIRED, 'ca_certs': cacert})
            if not expectSuccess:
                pytest.fail('Should not be able to connect with SSL client using server validation when providing certificate and key')
            self._putget(cluster, session)
        except NoHostAvailable:
            if expectSuccess:
                pytest.fail('Should be able to connect with SSL client using server validation when providing certificate and key')

    def _putget(self, cluster, session, ks='ks', cf='cf'):
        create_ks(session, ks, 1)
        create_cf(session, cf, compression=None)
        putget(cluster, session, cl=ConsistencyLevel.ONE)
