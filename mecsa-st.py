"""
Copyright 2018 European Commission

Licensed under the EUPL, Version 1.2 or as soon they will be approved by the European
Commission - subsequent versions of the EUPL (the "Licence");

You may not use this work except in compliance with the Licence.

You may obtain a copy of the Licence at:

https://joinup.ec.europa.eu/software/page/eupl

Unless required by applicable law or agreed to in writing, software distributed under the Licence is distributed
on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

See the Licence for the specific language governing permissions and limitations under the Licence.
"""
__author__ = 'Joint Research Centre (JRC) - E.3 Cyber and Digital Citizen\'s Security'

import argparse
import logging.handlers
import sys
import ssl
import io
import OpenSSL
from test_starttls import test_in_starttls
from test_x509 import test_x509
from test_x509 import cache_x509
from test_spf import test_spf
from test_dmarc import test_dmarc
from test_dane import test_dane
from test_dnssec import test_dnssec
from test_dnssec import cache_dnssec
from test_dkim import test_dkim
from test_mtasts import test_mta_sts


def init_report(mx, priority, ipv4, is_mx=True):
    """
    Generates a dictionary containing all values obtained during the assessment for StartTLS, x509 and DANE.

    :param mx: MX hostname
    :param priority: priority of the MX
    :param ipv4: IP address of the MX
    :param is_mx: boolean, indicates whether the domain has MX records or not.
    :return: Dictionary:

    ir_mx ---------------------  String, Mail Exchanger (MX) hostname
    ir_is_mx ------------------  Boolean, does the domain has MX? True:False (if False, ir_mx is the domain name)
    ir_mx_ipv4 ----------------  String, IPv4 address of ir_mx
    ir_mx_priority ------------  Integer, value representing the priority of ir_mx as MX of domain.
    ir_smtp_success -----------  Boolean, Was the SMTP connection with ir_mx successful? True:False
    ir_banner -----------------  String, The ir_mx SMTP connection banner
    ir_esmtp_features ---------  String, list of ESMTP features returned by ir_mx as answer to the HELO command
    ir_starttls ---------------  Boolean, does ir_mx support StartTLS? True:False
    ir_starttls_announced -----  Boolean, does ir_mx announces StartTLS in the ESMTP response? True:False
    ir_starttls_enc -----------  String, TLS protocol used, cipher and  keysize
    ir_certificate ------------  String, StartTLS certificate in .pem format
    ir_certificate_error ------  String, Message error if the certificate validation process fails
    ir_certificate_hash -------  String, SHA1 hash of the certificate
    ir_certificate_chain ------  String, StartTLS certificates trust chain in .pem format
    ir_certificate_ca_valid ---  Boolean, is the StartTLS certificate signed by a trusted CA? True:False
    ir_certificate_fqdn_valid -  Boolean, does either the CN or the SAN of the certificate match the ir_mx hostname?
    ir_certificate_date_valid -  Boolean, Is the date of the certificate valid? True:False
    ir_certificate_revocated --  Boolean, Is the certificate revoked, i.e. in the RCL list? True:False
    ir_has_tlsa ---------------  Boolean, Does ir_mx have a DNS TLSA registry?
    ir_valid_tlsa -------------  Boolean, is the ir_mx TLSA registry (if it has one) valid? True:False
    ir_tlsa_txt ---------------  String, DNS TLSA registry of ir_mx
    ir_tlsa_errors ------------  String, error (if any) when validating the DNS TLSA registry
    ir_valid_mta_sts ----------  Boolean, is the MTA-STS policy (if it has one) valid? True:False
    ir_mta_sts_errors ---------  String, error (if any) when validating the MTA-STS Policy
    ir_error  -----------------  String, General error message

    """

    report = {}
    report['ir_mx'] = mx
    report['ir_is_mx'] = is_mx
    report['ir_mx_ipv4'] = ipv4
    report['ir_mx_priority'] = priority
    report['ir_smtp_success'] = False
    report['ir_banner'] = None
    report['ir_esmtp_features'] = None
    report['ir_starttls'] = False
    report['ir_starttls_announced'] = False
    report['ir_starttls_enc'] = None
    report['ir_certificate'] = None
    report['ir_certificate_error'] = None
    report['ir_certificate_hash'] = None
    report['ir_certificate_chain'] = None
    report['ir_certificate_ca_valid'] = False
    report['ir_certificate_fqdn_valid'] = False
    report['ir_certificate_date_valid'] = False
    report['ir_certificate_revocated'] = False
    report['ir_has_tlsa'] = False
    report['ir_valid_tlsa'] = False
    report['ir_tlsa_txt'] = None
    report['ir_tlsa_errors'] = None
    report['ir_valid_mta_sts'] = False
    report['ir_mta_sts_errors'] = None
    report['ir_error'] = None
    return report


def init_spf_row(domain):
    """

    :param domain: domain name tested
    :return: Dictionary,

    domain -----------  String, domain name tested
    has_spf ----------  Boolean, indicates if the domain has a DNS SPF record
    spf_records ------  String, SPF records of the domain 'domain'
    syntax_check -----  Boolean, Does the SPF record passed the syntax check? True:False
    syntax_response --  String, response of the 'check_syntax'
    errors -----------  String, general error (if any) during the validation of the SPF

    """

    row = {}
    row['domain'] = domain
    row['has_spf'] = False
    row['spf_records'] = None
    row['syntax_check'] = False
    row['syntax_response'] = None
    row['errors'] = None
    return row


def init_dmarc_row(domain):
    """

    :param domain: domain name tested
    :return: Dictionary,

    domain -----------  String, domain name tested
    has_dmarc --------  Boolean, indicates if the domain has a DNS DMARC record
    dmarc_records ----  String, DMARC records of the domain 'domain'
    syntax_check -----  Boolean, Does the DMARC record passed the syntax check? True:False
    syntax_response --  String, response of the 'check_syntax'
    errors -----------  String, general error (if any) during the validation of the DMARC

    """

    row = {}
    row['domain'] = domain
    row['has_dmarc'] = False
    row['dmarc_records'] = None
    row['syntax_check'] = False
    row['syntax_response'] = None
    row['errors'] = None
    return row


def execute_starttls(logger, domain):
    """
    This function executes the StartTLS tests

    The test will first obtain all MX records of 'domain' (DNS MX request).

    For each MX record, it will attempt an SMTP connection, establish a TLS channel, and download the
    TLS certificate and the chain of intermediate certificates.

    :param logger: log object initialized
    :param domain: String, domain name tested.
    :return: List of 'init_report' dictionaries

    """

    logger.info('--------> Init StartTLS test')

    tester = test_in_starttls.TestStartTLS(logger)
    servers = tester.init_test(domain)
    test_results = []

    for server in servers:
        row = init_report(server['mx'], server['priority'], server['ipv4'], server['is_mx'])
        tester.supports_starttls(row)
        test_results.append(row)

    return test_results


def execute_x509(logger, root_cas, results, cache):
    logger.info('--------> Init x509 test')
    x509 = test_x509.TestCertificate(logger, root_cas, cache_x509=cache)
    for line in results:
        if line['ir_starttls']:
            x509.test_certificate(line)
    return results


def execute_spf(logger, domain):
    """
    This function executes the SPF test.

    The test will fetch the SPF record (DNS TXT request), and will check its syntax.

    :param logger: log object initialized
    :param domain: String, domain tested
    :return: dictionary (see init_spf_row function)
    """

    logger.info('--------> Init SPF test')
    row = init_spf_row(domain)
    tester = test_spf.Spf(logger)

    spf_row = tester.test_spf(domain)

    row['has_spf'] = spf_row['has_spf']
    row['spf_records'] = spf_row['spf_record']
    row['syntax_check'] = spf_row['spf_syntax_check']
    row['syntax_response'] = spf_row['spf_syntax_response']
    row['errors'] = spf_row['spf_error']
    return row


def execute_dkim(logger, domain):
    logger.info('--------> Init DKIM test')
    tester = test_dkim.DkimTest(logger)

    has_dkim, dkim_txt = tester.test_dkim(domain)

    return has_dkim, dkim_txt


def execute_dmarc(logger, domain, tlds_list):
    """
    This function executes the DMARC test.

    The test will first, fetch the DMARC record with a DNS TXT request to '_dmarc.<domain>'.
    If domain is a sub_domain and it does not have a DMARC record, it will try to obtain the DMARC record from
    the organizational domain of 'domain'.

    Once it has the DMARC record, it will check its syntax.


    :param logger: log object initialized
    :param domain: String, domain tested
    :param tlds_list:
    :return: dictionary (see init_damrc_row)
    """

    logger.info('--------> Init DMARC test')
    row = init_dmarc_row(domain)
    tester = test_dmarc.Dmarc(logger, tlds_list)

    dmarc_row = tester.test_dmarc(domain)

    row['has_dmarc'] = dmarc_row['has_dmarc']
    row['dmarc_records'] = dmarc_row['dmarc_record']
    row['syntax_check'] = dmarc_row['dmarc_syntax_check']
    row['syntax_response'] = dmarc_row['dmarc_syntax_response']
    row['errors'] = dmarc_row['dmarc_error']
    return row


def execute_dane(logger, reports, root_cas):
    """
    This function calls the DANE tests.

    For each MX that supports StartTLS, it will fetch its DNS TLSA record (_25._tcp.<domain>) and will validate its
    value against the certificate obtained when establishing the TLS connection with he MX.

    :param logger: log object initialized
    :param reports: list of 'init_report' dictionaries
    :param root_cas: list of root_cas accepted as trusted (default CA's from an Ubuntu distribution)
    :return: it fills the values 'ir_has_tlsa', 'ir_tlsa_txt', 'ir_tlsa' and 'ir_tlsa_errors'
             of the of 'init_report' list of dictionaries (reports).

    """
    logger.info('--------> Init TLSA test')

    tester = test_dane.DaneTLSA(logger, root_cas)
    tested = {}
    for report in reports:
        try:
            if report['ir_starttls']:
                #    To avoid fetching twice the same TLSA record. One MX may have many IPs, therefore
                # we may have several 'report' with the same MX, but different IPv4)
                if report['ir_mx'] not in tested:
                    report['ir_has_tlsa'], report['ir_tlsa_txt'] = tester.fetch_tlsa(report['ir_mx'])
                    cache_tlsa = {'has_tlsa': report['ir_has_tlsa'], 'tlsa_txt': list(report['ir_tlsa_txt'])}
                    tested[report['ir_mx']] = cache_tlsa
                else:
                    cached_tlsa = tested[report['ir_mx']]
                    report['ir_has_tlsa'] = cached_tlsa['has_tlsa']
                    report['ir_tlsa_txt'] = cached_tlsa['tlsa_txt']

                if report['ir_has_tlsa']:
                    errors = []
                    logger.info('MX %s HAS %d tlsa records:' % (report['ir_mx'], len(report['ir_tlsa_txt'])))
                    for tlsa in report['ir_tlsa_txt']:
                        dane_valid, dane_error = tester.execute(report['ir_certificate'],
                                                                report['ir_certificate_chain'], tlsa)
                        if dane_valid:
                            logger.info('MX %s HAS DANE: %s' % (report['ir_mx'], tlsa))
                            report['ir_tlsa_txt'] = tlsa
                            report['ir_valid_tlsa'] = True
                            report['ir_tlsa'] = True
                        else:
                            errors.append(dane_error)
                    report['ir_tlsa_errors'] = '\n'.join(errors)
        except Exception as ex:
            logger.error('GENERAL ERROR DANE %s' % str(ex))


def execute_dnssec(logger, domain, records, i_reports, cache=None):
    """
    This function calls the DNSSEC tests.

    1. test if 'domain' supports DNSSEC.
       if supported, test if the MX records are secured with DNSSEC.
    2. test if the MX records (mx_test) of 'domain' support DNSSEC.
        for each MX:
        2.1 test if the MX hostname supports DNSSEC
        2.2 test if the MX records have the A records secured with DNSSEC
    3. test if the TXT (SPF) records of 'domain' are secured with DNSSEC (optional)
    4. test if the DMARC records of 'domain' are secured with DNSSEC (optional)
    5. test if the TLSA records of 'domain' are secured with DNSSSEC (optional)

    :param logger: log object initialized
    :param domain: String, domain tested
    :param records: List of DNS types and domains that the function will test.
    :param i_reports: list of 'init_report' dictionaries
    :param cache: an local cache of DNS records, to avoid repeating DNS requests.
    :return: A list of 'init_dd_row' dictionaries (see function 'init_dd_row' in 'test_dnssec.py')
    """
    logger.info("--------> Init DNSSEC test (%s)" % str(records))

    tester = test_dnssec.Dnssec(logger, cache)

    mxs = []
    for report in i_reports:
        if report['ir_smtp_success']:
            mxs.append(report['ir_mx'])
    tlsas = []
    if 'TLSA' in records:
        tester.set_tlsa_test(True)
        for report in i_reports:
            if report['ir_has_tlsa']:
                tlsas.append(report['ir_mx'])
    if 'TXT' in records:
        tester.set_txt_test(True)
    if 'DMARC' in records:
        tester.set_dmarc_test(True)

    return tester.execute_test(domain, mxs, tlsas)


def execute_mta_sts(logger, domain, records):
    """

    :param logger: log object initialized
    :param domain: domain name tested
    :param records: dictionary, see function init_report
    :return: dictionary, records updated with mta-sts values (see function init_report)
             dictionary, mta_sts dictionary (see function test_mta_sts.MtaSts.init_mta_sts_parameters)

    """
    row_mta_sts = None
    try:
        logger.info('---> Init MTA-STS test on domain %s' % domain)
        tester = test_mta_sts.MtaSts(logger)
        row_mta_sts = tester.test_mta_sts(domain)
        if row_mta_sts['has_mta_sts']:
            tester.validate_policy(row_mta_sts['mta_sts_policy'], records)
    except Exception as ex:
        logger.error("Error Testing MTA-STS for domain %s (%s)" % (domain, str(ex)))
    return records, row_mta_sts


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
        logger.error('loading CAs from %s (%s)' % (filepath, str(ex)))
        return []


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
        logger.error('loading TLDS from %s (%s)' % (suffix_list_file, str(ex)))
        return []


def run_full_tests(logger, domain, filepath):
    """
    Main function, that initializes and executes all the tests

    :param logger: log object initialized
    :param domain: String, domain name tested
    :param commands: List of tests to execute.
    :param filepath: file from where to load the CA certificates (default: '/etc/ssl/certs/ca-certificates.crt')
    :return: Prints the results.
    """
    try:
        root_cas = load_cas(logger, filepath)
        tlds_list = load_tlds(logger)
        logger.debug('---- TLDS LIST SIZE %d -----' % len(tlds_list))
        dnssec_cache = cache_dnssec.CacheDnssec(logger)
        x509_cache = cache_x509.CacheX509(logger)

        logger.info('---> Init test on domain %s' % domain)
        test_records = []

        # Testing StartTLS
        inbound_reports = execute_starttls(logger, domain)
        if len(inbound_reports) > 0:
            # Testing x509
            execute_x509(logger, root_cas, inbound_reports, x509_cache)

            # Testing SPF
            spf_report = execute_spf(logger, domain)
            if spf_report['has_spf'] and spf_report['syntax_check']:
                test_records.append('TXT')

            # Testing DKIM
            has_dkim, dkim_txt = execute_dkim(logger, domain)

            # Testing DMARC
            dmarc_report = execute_dmarc(logger, domain, tlds_list)
            if dmarc_report['has_dmarc'] and dmarc_report['syntax_check']:
                test_records.append('DMARC')

            # Testing DANE
            execute_dane(logger, inbound_reports, root_cas)
            for report in inbound_reports:
                if report['ir_has_tlsa'] and 'TLSA' not in test_records:
                    test_records.append('TLSA')

            # Testing DNSSEC
            dnssec_report = execute_dnssec(logger, domain, test_records, inbound_reports, dnssec_cache)

            # Testing MTA-STS
            inbound_reports, mta_sts_report = execute_mta_sts(logger, domain, inbound_reports)

            # RESULTS
            logger.info('\n\n\n\n---- REPORT FOR DOMAIN %s -----' % domain)
            logger.info('---- domain has %d MX records. ' % len(inbound_reports))

            for report in inbound_reports:

                if report['ir_starttls']:
                    logger.info('---- STARTTLS ENABLED %s %s %s   ' % (report['ir_mx'],
                                                                       report['ir_mx_ipv4'],
                                                                       str(report['ir_mx_priority'])))
                    logger.info('-------- StartTLS announced? %s' % str(report['ir_starttls_announced']))
                    logger.info('-------- %s (protocol, cipher, keysize)' % report['ir_starttls_enc'])
                    logger.info('-------- x509 CA validated %s' % str(report['ir_certificate_ca_valid']))
                    logger.info('-------- x509 FQDN match MX %s' % str(report['ir_certificate_fqdn_valid']))
                    logger.info('-------- x509 Date Valid  %s' % str(report['ir_certificate_date_valid']))
                    logger.info('-------- x509 Revocated %s' % str(report['ir_certificate_revocated']))
                    if report['ir_valid_tlsa']:
                        logger.info('-------- DANE ENABLED')
                        logger.info('-------- TLSA record: %s' % str(report['ir_tlsa_txt']))
                    else:
                        logger.info('-------- DANE DISABLED')
                        logger.info('-------- TLSA record %s' % str(report['ir_has_tlsa']))
                        if report['ir_has_tlsa']:
                            logger.info('-------- Records: %s' % report['ir_tlsa_txt'])
                            logger.info('-------- ERRORS (%s)' % report['ir_tlsa_errors'])
                    if mta_sts_report['has_mta_sts']:
                        if report['ir_valid_mta_sts']:
                            logger.info('-------- MTA-STS MX COMPLIES with POLICY')
                        else:
                            logger.info('-------- MTA-STS NOT! POLICY COMPLIANT')

                else:
                    logger.info('---- %s %s %s STARTTLS DISABLED  ' % (report['ir_mx'],
                                                                       report['ir_mx_ipv4'],
                                                                       str(report['ir_mx_priority'])))
                    logger.info('-------- Error: (%s)' % report['ir_error'])

            if spf_report['has_spf'] and spf_report['syntax_check']:
                logger.info('---- SPF ENABLED')
                logger.info('-------- spf record: %s ' % str(spf_report['spf_records']))
            else:
                logger.info('---- SPF DISABLED')
                logger.info('-------- Errors (%s)' % str(spf_report['errors']))
                logger.info('-------- Syntax check (%s)' % str(spf_report['syntax_response']))

            if has_dkim:
                logger.info('---- DKIM ENABLED')
            else:
                logger.info('---- DKIM DISABLED')
            logger.info('-------- test response: %s ' % str(dkim_txt))

            if dmarc_report['has_dmarc'] and dmarc_report['syntax_check']:
                logger.info('---- DMARC ENABLED')
                logger.info('-------- dmarc record: %s ' % str(dmarc_report['dmarc_records']))
            else:
                logger.info('---- DMARC DISABLED')
                logger.info('-------- Errors (%s)' % str(dmarc_report['errors']))
                logger.info('-------- Syntax Check (%s)' % str(dmarc_report['syntax_response']))

            if dnssec_report['dd_dnssec']:
                logger.info('---- DNSSEC ENABLED')
            else:
                logger.info('---- DNSSEC DISABLED')
                logger.info('-------- dnssec MX %s' % dnssec_report['dd_dnssec_mx'])
                logger.info('-------- dnssec MX-A %s' % dnssec_report['dd_dnssec_mx_a'])
                if spf_report['has_spf'] and spf_report['syntax_check']:
                    logger.info('-------- dnssec TXT %s' % dnssec_report['dd_dnssec_spf'])
                if dmarc_report['has_dmarc'] and dmarc_report['syntax_check']:
                    logger.info('-------- dnssec DMARC %s' % dnssec_report['dd_dnssec_spf'])
                if report['ir_has_tlsa']:
                    logger.info('-------- dnssec TLSA %s' % dnssec_report['dd_dnssec_tlsa'])
                logger.info('-------- error %s' % dnssec_report['dd_error'])

            if mta_sts_report['has_mta_sts']:
                logger.info('---- MTA-STS ENABLED :')
                logger.info('-------- DNS Record      : %s' % mta_sts_report['mta_sts_dns'])
                logger.info('-------- Policy Version  : %s' % mta_sts_report['mta_sts_policy']['version'])
                logger.info('-------- Policy Mode     : %s' % mta_sts_report['mta_sts_policy']['mode'])
                logger.info('-------- Policy MX       : %s' % mta_sts_report['mta_sts_policy']['mx'])
                logger.info('-------- Policy max-age  : %s' % mta_sts_report['mta_sts_policy']['max_age'])
            else:
                logger.info('-------- Has DNS       : %s' % str(mta_sts_report['has_mta_sts_dns']))
                logger.info('-------- Has Policy    : %s' % str(mta_sts_report['has_mta_sts_policy']))
                logger.info('-------- MTA-STS errors: %s' % str(mta_sts_report['mta_sts_error']))

            logger.info('---> END of TEST -----------------------------------------------------------\n')
        else:
            logger.info('---> Domain %s Does not have MX records' % domain)

    except Exception as ex:
        logger.error("General ERROR (%s) " % str(ex))


parser = argparse.ArgumentParser(description='MECSA Standalone Test')
parser.add_argument('domain', help='domain to test')
parser.add_argument('-l', '--log', help='specify path and name of logfile. Default is mecsa-st.log ')
parser.add_argument('-c', '--certificates',
                    help='specify path from where to load the CA certificates. Default is \'/etc/ssl/certs/ca-certificates.crt\'')
args = parser.parse_args()

if args.log:
    path_log = args.log
else:
    path_log = 'mecsa-st.log'

if args.certificates:
    filepath = args.certificates
else:
    filepath = '/etc/ssl/certs/ca-certificates.crt'

logger = logging.getLogger('MECSA-ST')
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger.setLevel(logging.DEBUG)

chf = logging.FileHandler(path_log)
chf.setLevel(logging.DEBUG)
chf.setFormatter(formatter)
logger.addHandler(chf)

chs = logging.StreamHandler()
chs.setLevel(logging.INFO)
chs.setFormatter(formatter)
logger.addHandler(chs)

if args.domain:
    domain = args.domain
else:
    error_exit = "Missing domain to test! Please use -d <domain> to indicate the domain you want to assess."
    logger.warning(error_exit)
    sys.exit(-1)

run_full_tests(logger, domain, filepath)
