import logging.handlers
import spf_checks.spf as mecsaspf

valid_spf_records = ['v=spf1 include:_spf.google.com ~all', 'v=spf1 ip4:192.168.0.0/16 include:_spf.google.com ~all', 'v=spf1 ptr ~all']
invalid_spf_records = ['v=spf1 a mx ip4:192.168.0.1 incude:example.com -all', 'v=spf1 a mx ip4:192.168.0. -all', 'v=spf a mx ip4:192.168.0.1 -all']
domain = "google.com"

logger = logging.getLogger('MECSA-ST')

def test_check_syntax_spf():
    logger.info('Init SPF test')

    spf_tester = mecsaspf.Spf(logger)
    
    #check valid records
    for record in valid_spf_records:
        valid, code, description = spf_tester.check_syntax_spf(record, domain)
        assert valid == True

    #check invalid records
    for record in invalid_spf_records:
        valid, code, description = spf_tester.check_syntax_spf(record, domain)
        assert valid == False