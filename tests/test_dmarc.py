import logging.handlers
import io
from dmarc_checks import dmarc

subdomain = "drive.google.com"
logger = logging.getLogger('MECSA-ST')

valid_dmark_entries = ['v=DMARC1; p=none; rua=mailto:mailauth-reports@google.com']
invalid_dmark_entries = ['v=DMARC; p=none; rua=mailto:mailauth-reports@google.com']

def test_dmarc_syntax():
    logger.info('Init DMARC test')

    tlds_list = load_tlds(logger)
    dmarc_tester = dmarc.Dmarc(logger, tlds_list)

    for entry in valid_dmark_entries:
        valid, obj1, obj2 = dmarc_tester.check_dmarc_syntax(entry)
        assert valid == True

    for entry in invalid_dmark_entries:
        valid, obj1, obj2 = dmarc_tester.check_dmarc_syntax(entry)
        assert valid == False    

def test_find_dmarc_org_domain():
    logger.info('Init SPF test')

    tlds_list = load_tlds(logger)
    dmarc_tester = dmarc.Dmarc(logger, tlds_list)

    org_domain, obj = dmarc_tester.find_organizational_domain(subdomain)

    assert org_domain == 'google.com'

def load_tlds(logger):
    """
    Loads the .tld file descriptor.

    :param logger: log object initialized
    :return: list of .tld domains
    """
    try:
        suffix_list_file = "public_suffix_list.dat"
        source = io.open(suffix_list_file, "r", encoding="utf-8")
        lines = source.readlines()
        tlds = []
        for line in lines:
            if not line.startswith("//"):
                tlds.append(line.rstrip('\n'))
        return tlds
    except Exception as ex:
        logger.error('loading TLDS from {0} ({1})'.format(suffix_list_file, str(ex)))
        return []

    