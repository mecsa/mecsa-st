import logging.handlers
import dkim_checks.dkim as dkim

valid_dkim_domains = ['google.com.']
invalid_dkim_domains = ['none']

logger = logging.getLogger('MECSA-ST')

def test_dkim():
    logger.info('Init DKIM test')

    dkim_tester = dkim.DkimTest(logger)
    
    #check valid records
    for domain in valid_dkim_domains:
        valid, description = dkim_tester.test_dkim(domain, 'A')
        assert valid == True

    #check invalid records
    for domain in invalid_dkim_domains:
        valid, description = dkim_tester.test_dkim(domain, 'A')
        assert valid == False