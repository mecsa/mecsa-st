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

__name__ = 'mecsa-st'
__version__= '2.0'


import sys
if (sys.version_info < (3, 0)):
    print("ERROR: this program requires python 3 to run. See README for more information")
    exit(1)

import argparse
import logging.handlers
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
from test_tlsrpt import test_tlsrpt
from test_mtasts import test_mta_sts
from commons import scoring

def banner():
	print("%s version %s\n" % (__name__, __version__))
	

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
    ir_requiretls_announced -----  Boolean, does ir_mx announces RequireTLS in the ESMTP response? True:False
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
    report['ir_requiretls_announced'] = False
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
    report['ir_tlsa'] = False
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

def init_tlsrpt_row(domain):
    """

    :param domain: domain name tested
    :return: Dictionary,

    domain -----------  String, domain name tested
    has_tlsrpt ----------  Boolean, indicates if the domain has a DNS TLS RPT record
    tlsrpt_records ------  String, TLS RPT records of the domain 'domain'
    syntax_check -----  Boolean, Does the TLS RPT record passed the syntax check? True:False
    syntax_response --  String, response of the 'check_syntax'
    errors -----------  String, general error (if any) during the validation of the TLS RPT

    """

    row = {}
    row['domain'] = domain
    row['has_tlsrpt'] = False
    row['tlsrpt_records'] = None
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

    return spf_row

def execute_tlsrpt(logger, domain):
    """
    This function executes the TLS RPT test.

    The test will fetch the TLS RPT record (DNS TXT request), and will check its syntax.

    :param logger: log object initialized
    :param domain: String, domain tested
    :return: dictionary (see init_tlsrpt_row function)
    """

    logger.info('--------> Init TLS RPT test')
    row = init_tlsrpt_row(domain)
    tester = test_tlsrpt.Tlsrpt(logger)

    tlsrpt_row = tester.test_tlsrpt(domain)

    return tlsrpt_row


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

    return dmarc_row


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
                    logger.info('MX {0} HAS {1} tlsa records:'.format(report['ir_mx'], len(report['ir_tlsa_txt'])))
                    for tlsa in report['ir_tlsa_txt']:
                        dane_valid, dane_error = tester.execute(report['ir_certificate'],
                                                                report['ir_certificate_chain'], tlsa)
                        if dane_valid:
                            logger.info('MX {0} HAS DANE: {0}'.format(report['ir_mx'], tlsa))
                            report['ir_tlsa_txt'] = tlsa
                            report['ir_valid_tlsa'] = True
                            report['ir_tlsa'] = True
                        else:
                            errors.append(dane_error)
                    report['ir_tlsa_errors'] = '\n'.join(errors)
        except Exception as ex:
            logger.error('GENERAL ERROR DANE {0}'.format(ex))


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
    logger.info("--------> Init DNSSEC test ({0})".format(records))

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
        logger.info('---> Init MTA-STS test on domain {0}'.format(domain))
        tester = test_mta_sts.MtaSts(logger)
        row_mta_sts = tester.test_mta_sts(domain)
        if row_mta_sts['has_mta_sts']:
            tester.validate_policy(row_mta_sts['mta_sts_policy'], records)
    except Exception as ex:
        logger.error("Error Testing MTA-STS for domain {0} ({1})".format(domain, ex))
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
        logger.error('loading CAs from {0} ({1})'.format(filepath, str(ex)))
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
        logger.error('loading TLDS from {0} ({1})'.format(suffix_list_file, str(ex)))
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
        logger.debug('---- TLDS LIST SIZE {0} -----'.format(len(tlds_list)))
        dnssec_cache = cache_dnssec.CacheDnssec(logger)
        x509_cache = cache_x509.CacheX509(logger)

        logger.info('---> Init test on domain {0}'.format(domain))
        test_records = []

        # Testing StartTLS
        inbound_reports = execute_starttls(logger, domain)
        if len(inbound_reports) > 0:
            # Testing x509
            execute_x509(logger, root_cas, inbound_reports, x509_cache)

            # Testing SPF
            spf_report = execute_spf(logger, domain)
            if spf_report['has_spf'] and spf_report['spf_syntax_check']:
                test_records.append('TXT')
                spf_report['supports_spf'] = True
                spf_report['spf_txt'] = spf_report['spf_record']
            else:
                spf_report['supports_spf'] = False
                spf_report['spf_txt'] = spf_report['spf_error']

            # Testing DKIM
            has_dkim, dkim_txt = execute_dkim(logger, domain)
            
            # Testing TLSRPT
            #has_tlsrpt, tlsrpt_txt = execute_tlsrpt(logger, domain)
            tlsrpt_report = execute_tlsrpt(logger, domain)
            if tlsrpt_report['has_tlsrpt'] and tlsrpt_report['tlsrpt_syntax_check']:
                test_records.append('TXT')
                tlsrpt_report['supports_tlsrpt'] = True
                tlsrpt_report['tlsrpt_txt'] = tlsrpt_report['tlsrpt_record']
            else:
                tlsrpt_report['supports_tlsrpt'] = False
                tlsrpt_report['tlsrpt_txt'] = tlsrpt_report['tlsrpt_error']
            
            # Testing DMARC
            dmarc_report = execute_dmarc(logger, domain, tlds_list)
            if dmarc_report['has_dmarc'] and dmarc_report['dmarc_syntax_check']:
                test_records.append('DMARC')
                dmarc_report['supports_dmarc'] = True
                dmarc_report['dmarc_txt'] = dmarc_report['dmarc_record']
            else:
                dmarc_report['supports_dmarc'] = False
                dmarc_report['dmarc_txt'] = dmarc_report['dmarc_error']


            # Testing DANE
            execute_dane(logger, inbound_reports, root_cas)
            for report in inbound_reports:
                if report['ir_has_tlsa'] and 'TLSA' not in test_records:
                    test_records.append('TLSA')

            # Testing DNSSEC
            dnssec_report = execute_dnssec(logger, domain, test_records, inbound_reports, dnssec_cache)

            # Testing MTA-STS
            inbound_reports, mta_sts_report = execute_mta_sts(logger, domain, inbound_reports)

            # Calculating values for Summary Report
            score_points = scoring.load_score_function(logger)
            score = scoring.ScoreOperations(logger, score_points)
            scores = score.domain_update(
                inbound_reports, [], dnssec_report, dmarc_report, spf_report, mta_sts_report, tlsrpt_report,
                (has_dkim, dkim_txt))

            # RESULTS
            logger.info('\n\n\n\n---- REPORT FOR DOMAIN {0} -----'.format(domain))
            logger.info('---- domain has {0} MX records. '.format(len(inbound_reports)))

            for report in inbound_reports:

                if report['ir_starttls']:
                    logger.info('---- STARTTLS ENABLED {0} {1} {2}   '.format(report['ir_mx'],
                                                                              report['ir_mx_ipv4'],
                                                                              report['ir_mx_priority']))
                    logger.info('-------- StartTLS announced: {0}'.format(report['ir_starttls_announced']))
                    if report['ir_requiretls_announced']:
                        logger.info('-------- REQUIRETLS ENABLED')
                    else:
                        logger.info('-------- REQUIRETLS DISABLED')
                    logger.info('-------- {0} (protocol, cipher, keysize)'.format(report['ir_starttls_enc']))
                    logger.info('-------- x509 CA validated {0}'.format(report['ir_certificate_ca_valid']))
                    logger.info('-------- x509 FQDN match MX {0}'.format(report['ir_certificate_fqdn_valid']))
                    logger.info('-------- x509 Date Valid  {0}'.format(report['ir_certificate_date_valid']))
                    logger.info('-------- x509 Revocated {0}'.format(report['ir_certificate_revocated']))
                    if report['ir_valid_tlsa']:
                        logger.info('-------- DANE ENABLED')
                        logger.info('-------- TLSA record: {0}'.format(report['ir_tlsa_txt']))
                    else:
                        logger.info('-------- DANE DISABLED')
                        logger.info('-------- TLSA record {0}'.format(report['ir_has_tlsa']))
                        if report['ir_has_tlsa']:
                            logger.info('-------- Records: {0}'.format(report['ir_tlsa_txt']))
                            logger.info('-------- ERRORS ({0})'.format(report['ir_tlsa_errors']))
                    if mta_sts_report['has_mta_sts']:
                        if report['ir_valid_mta_sts']:
                            logger.info('-------- MTA-STS MX COMPLIES with POLICY')
                        else:
                            logger.info('-------- MTA-STS NOT! POLICY COMPLIANT')

                else:
                    logger.info('---- {0} {1} {2} STARTTLS DISABLED  '.format(report['ir_mx'],
                                                                              report['ir_mx_ipv4'],
                                                                              report['ir_mx_priority']))
                    logger.info('-------- Error: ({0})'.format(report['ir_error']))
            
            if spf_report['has_spf'] and spf_report['spf_syntax_check']:
                logger.info('---- SPF ENABLED')
                logger.info('-------- spf record: {0} '.format(spf_report['spf_record']))
            else:
                logger.info('---- SPF DISABLED')
                logger.info('-------- Errors ({0})'.format(spf_report['spf_error']))
                logger.info('-------- Syntax check ({0})'.format(spf_report['spf_syntax_response']))

            if tlsrpt_report['has_tlsrpt'] and tlsrpt_report['tlsrpt_syntax_check']:
                logger.info('---- TLS RPT ENABLED')
                logger.info('-------- tlsrpt record: {0} '.format(tlsrpt_report['tlsrpt_record']))
            else:
                logger.info('---- TLS RPT DISABLED')
                logger.info('-------- Errors ({0})'.format(tlsrpt_report['tlsrpt_error']))
                logger.info('-------- Syntax check ({0})'.format(tlsrpt_report['tlsrpt_syntax_check']))

            if has_dkim:
                logger.info('---- DKIM ENABLED')
            else:
                logger.info('---- DKIM DISABLED')
            logger.info('-------- test response: {0} '.format(dkim_txt))

            if dmarc_report['has_dmarc'] and dmarc_report['dmarc_syntax_check']:
                logger.info('---- DMARC ENABLED')
                logger.info('-------- dmarc record: {0}'.format(dmarc_report['dmarc_record']))
            else:
                logger.info('---- DMARC DISABLED')
                logger.info('-------- Errors ({0})'.format(dmarc_report['dmarc_error']))
                logger.info('-------- Syntax Check ({0})'.format(dmarc_report['dmarc_syntax_response']))

            if dnssec_report['dd_dnssec']:
                logger.info('---- DNSSEC ENABLED')
            else:
                logger.info('---- DNSSEC DISABLED')
                logger.info('-------- dnssec MX {0}'.format(dnssec_report['dd_dnssec_mx']))
                logger.info('-------- dnssec MX-A {0}'.format(dnssec_report['dd_dnssec_mx_a']))
                if spf_report['has_spf'] and spf_report['spf_syntax_check']:
                    logger.info('-------- dnssec TXT {0}'.format(dnssec_report['dd_dnssec_spf']))
                if dmarc_report['has_dmarc'] and dmarc_report['dmarc_syntax_check']:
                    logger.info('-------- dnssec DMARC {0}'.format(dnssec_report['dd_dnssec_spf']))
                if report['ir_has_tlsa']:
                    logger.info('-------- dnssec TLSA {0}'.format(dnssec_report['dd_dnssec_tlsa']))
                logger.info('-------- error {0}'.format(dnssec_report['dd_error']))

            if mta_sts_report['has_mta_sts']:
                logger.info('---- MTA-STS ENABLED :')
                logger.info('-------- DNS Record      : {0}'.format(mta_sts_report['mta_sts_dns']))
                logger.info('-------- Policy Version  : {0}'.format(mta_sts_report['mta_sts_policy']['version']))
                logger.info('-------- Policy Mode     : {0}'.format(mta_sts_report['mta_sts_policy']['mode']))
                logger.info('-------- Policy MX       : {0}'.format(mta_sts_report['mta_sts_policy']['mx']))
                logger.info('-------- Policy max-age  : {0}'.format(mta_sts_report['mta_sts_policy']['max_age']))
            else:
                logger.info('---- MTA-STS DISABLED :')
                logger.info('-------- Has DNS       : {0}'.format(mta_sts_report['has_mta_sts_dns']))
                logger.info('-------- Has Policy    : {0}'.format(mta_sts_report['has_mta_sts_policy']))
                logger.info('-------- MTA-STS errors: {0}'.format(mta_sts_report['mta_sts_error']))

            logger.info('---------------------------------------------------------------------------\n')
            logger.info('---> SUMMARY REPORT for domain {0}  --------------------------------------'.format(domain))
            logger.info('---> ')
            logger.info('---> Confidentiality {:.1f}'.format(scores['dr_confidential']/2)) 
            logger.info('---> Spoofing        {:.1f}'.format(scores['dr_spoofing']/2))
            logger.info('---> Integrity       {:.1f}'.format(scores['dr_integrity']/2))
            logger.info('---> ')
            conf_protocols = score.get_summary('confidentiality')[0]
            conf_missing = score.get_summary('confidentiality')[2]
            spoof_protocols = score.get_summary('spoofing')[0]
            spoof_missing = score.get_summary('spoofing')[2]
            int_protocols = score.get_summary('integrity')[0]
            int_missing = score.get_summary('integrity')[2]
            logger.info('---> **** Confidentiality evaluated on: {0}'.format(conf_protocols))
            logger.info('---> **** Missing                     : {0}'.format(conf_missing))
            logger.info('---> ****  ****')
            logger.info('---> **** Spoofing evaluated on       : {0}'.format(spoof_protocols))
            logger.info('---> **** Missing                     : {0}'.format(spoof_missing))
            logger.info('---> ****  ****')
            logger.info('---> **** Integrity evaluated on      : {0}'.format(int_protocols))
            logger.info('---> **** Missing                     : {0}'.format(int_missing))
            logger.info('---> ****  ****')
            logger.info('---> **** These results might differ from the ones given by the MECSA platform ****')
            logger.info('---> **** because we have less data. MECSA also has outbound tests:            ****')
            logger.info('---> **** _ StartTLS check on email delivery                                   ****')
            logger.info('---> **** _ SPF policy verification on delivery servers                        ****')
            logger.info('---> **** _ DKIM signature check                                               ****')
            logger.info('---> ****                                                                      ****')
            logger.info('---> **** https://mecsa.jrc.ec.europa.eu                                       ****')
            logger.info('---> ')
            logger.info('---> END of TEST -----------------------------------------------------------\n')
        else:
            logger.info('---> Domain {0} Does not have MX records'.format(domain))

    except Exception as ex:
        logger.error("General ERROR ({0}) ".format(ex))


banner()

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
formatter_file = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
formatter_console = logging.Formatter('%(name)s - %(levelname)s - %(message)s')
logger.setLevel(logging.DEBUG)

chf = logging.FileHandler(path_log)
chf.setLevel(logging.DEBUG)
chf.setFormatter(formatter_file)
logger.addHandler(chf)

chs = logging.StreamHandler()
chs.setLevel(logging.INFO)
chs.setFormatter(formatter_console)
logger.addHandler(chs)

if args.domain:
    domain = args.domain
else:
    error_exit = "Missing domain to test! Please use -d <domain> to indicate the domain you want to assess."
    logger.warning(error_exit)
    sys.exit(-1)

logger.info(__author__)
logger.info("{0} v{1}".format(__name__, __version__))
logger.info('')
run_full_tests(logger, domain, filepath)
