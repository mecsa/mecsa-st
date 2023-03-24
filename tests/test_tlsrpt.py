import logging.handlers
import tlsrpt_checks.tlsrpt as tlsrpt

valid_domains = ['google.com.']
invalid_domains = ['none']

logger = logging.getLogger('MECSA-ST')

def test_dkim():
    logger.info('Init DKIM test')

    tlsrpt_tester = tlsrpt.Tlsrpt(logger)

    #check valid records
    for domain in valid_domains:
        res, record, error = tlsrpt_tester.fecth_tlsrpt(domain)
        assert record != None

    #check invalid records
    for domain in invalid_domains:
        res, record, error = tlsrpt_tester.fecth_tlsrpt(domain)
        assert record == None
