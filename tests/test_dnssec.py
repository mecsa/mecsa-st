import logging.handlers
from pickle import TRUE
from dnssec_checks import dnssec

domain = "google.com."

logger = logging.getLogger('MECSA-ST')

def test_check_subdomain():
    logger.info('Init DNSSEC test')

    dns_tester = dnssec.Dnssec(logger)
    
    #check valid records
    list, error  = dns_tester.getSOA_list(domain)

    assert list != None

    ns, ips = dns_tester.getNS(domain)

    assert ns != None
