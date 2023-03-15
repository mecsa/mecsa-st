import logging.handlers
import tlsrpt_checks.tlsrpt as tlsrpt
import starttls_checks.starttls as starttls

filepath = '/etc/ssl/certs/ca-certificates.crt'
logger = logging.getLogger('MECSA-ST')

domain = "google.com"

def test_fecth_records():
    logger.info('Init starttls test')
    tester = starttls.TestStartTLS(logger)

    valid, records, error = tester.fetch_records(domain, 'A')

    assert valid == True and records != None

def test_mx():
    logger.info('Init starttls test')
    tester = starttls.TestStartTLS(logger)

    valid, records, error = tester.fetch_mx(domain)

    assert valid == True and records != None

def test_tls():
    logger.info('Init tls test')

    tester = tlsrpt.Tlsrpt(logger)

    tls_rpt, record, error = tester.fecth_tlsrpt(domain)

    assert tls_rpt == True and "v=tlsrpt" in record.lower()
