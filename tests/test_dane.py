import logging.handlers
import dane_checks.dane
import OpenSSL
import ssl

valid_hosts = ['google.com']
invalid_hosts = ['localhost']

filepath = '/etc/ssl/certs/ca-certificates.crt'
logger = logging.getLogger('MECSA-ST')

def load_cas(logger, filepath):
    """
    Loads the default Root-CA certificates for Ubuntu.

    :param logger: log object initialized
    :param filepath: file from where to load the CA certificates (default: '/etc/ssl/certs/ca-certificates.crt')
    :return: a list of CAs certificates.
    """

    try:
        ca_certs = []
        context = ssl.create_default_context()
        context.load_verify_locations(filepath)
        certs = context.get_ca_certs(binary_form=True)
        for cert in certs:
            c = OpenSSL.crypto
            ca_certs.append(c.load_certificate(c.FILETYPE_ASN1, cert))
        return ca_certs
    except Exception as ex:
        logger.error('loading CAs from {0} ({1})'.format(filepath, str(ex)))
        return []

def test_dane():
    logger.info('Init SPF test')
    root_cas = load_cas(logger, filepath)

    dane_tester = dane_checks.dane.DaneTLSA(logger, root_cas)
    
    #check valid records
    for mx in valid_hosts:
        valid, log = dane_tester.test_tlsa(mx)
        assert valid == False and "NXDOMAIN" in log[0]

    #check invalid records
    for mx in invalid_hosts:
        valid, log = dane_tester.test_tlsa(mx)
        assert valid == False #and "NoAnswer" in log[0]