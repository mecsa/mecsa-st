import logging.handlers
import mtasts_checks.mta_sts as mtasts

valid_domains = ['google.com.']
invalid_domains = ['none']

logger = logging.getLogger('MECSA-ST')

def test_dkim():
    logger.info('Init DKIM test')

    mtasts_tester = mtasts.MtaSts(logger)

    #check valid records
    for domain in valid_domains:
        dns, record, error = mtasts_tester.fetch_mta_sts_dns(domain)
        assert record != None

    #check invalid records
    for domain in invalid_domains:
        dns, record, error = mtasts_tester.fetch_mta_sts_dns(domain)
        assert record == None
