import hashlib
import json
from test_spf import test_spf


def load_score_function(logger):
    """
    This class loads the score table to calculate the summary report
    from the json file 'commons/score.json':

    {"confidentiality":{
        "protocols" : "",
        "10" : "",
        ...
        "1" : ""
        },
    "spoofing":{
        "protocols" : "",
        "10" : "",
        ...
        "1" : ""
        },
    "integrity":{
        "protocols" : "",
        "10" : "",
        ...
        "1" : ""
        }        
    }

    """
    try:
        lines = open("commons/score.json", "r").read()
        tmp_dict = json.loads(lines)
        keys = tmp_dict.keys()

        scores = ["1", "2", "3", "4", "5", "6", "7", "8", "9", "10"]
        pointer = {}

        for key in keys:
            category = tmp_dict[key]
            pointer[key] = category['protocols']
            for score in scores:
                combinations = category[score]
                if len(combinations) > 0:
                    for combination in combinations:
                        index = hashlib.sha1(combination.encode()).hexdigest()
                        pointer[index] = score
        return pointer
    except Exception as ex:
        logger.warning("Error loading score function (%s)" % str(ex))
        return ""


def init_domain_update():
    values = {}
    values['dr_confidential'] = 0
    values['dr_spoofing'] = 0
    values['dr_integrity'] = 0
    values['dr_starttls'] = 0
    values['dr_certificate'] = 0
    values['dr_mx_records'] = 0
    values['dr_out_records'] = 0
    values['dr_spf'] = 0
    values['dr_spf_txt'] = None
    values['dr_has_spf_record'] = False
    values['dr_valid_spf_syntax'] = False
    values['dr_dkim'] = 0
    values['dr_dkim_txt'] = None
    values['dr_dmarc'] = 0
    values['dr_dmarc_txt'] = None
    values['dr_has_dmarc_record'] = False
    values['dr_valid_dmarc_syntax'] = False
    values['dr_smtp_sts'] = 0
    values['dr_smtp_sts_txt'] = None
    values['dr_dane'] = 0
    values['dr_dane_txt'] = None
    values['dr_dnssec'] = 0
    values['dr_dnssec_txt'] = None
    values['dr_mta_sts'] = 0
    values['dr_has_mta_sts'] = False
    values['dr_has_mta_sts_dns'] = False
    values['dr_mta_sts_dns_syntax'] = False
    values['dr_mta_sts_dns'] = None
    values['dr_has_mta_sts_policy'] = False
    values['dr_mta_sts_policy_syntax'] = False
    values['dr_mta_sts_policy'] = None
    values['dr_mta_sts_error'] = None
    return values


class ScoreOperations():

    def __init__(self, logger, scores):
        self.logger = logger
        self.scores = scores
        self.scored = {}

    def get_summary(self, category):
        try:
            diference = []
            protocols = self.scores[category].split(',')
            assessed = self.scored[category]
            for protocol in protocols:
                if protocol not in assessed:
                    diference.append(protocol)
            if len(diference) > 0:
                missing = ",".join(diference)
            else:
                missing = "No protocols missing! congrats."
        except Exception as ex:
            self.logger.warning("ScoreOperations.get_summary({0}) [{1}]".format(category, ex))
            missing = "Error getting missing protocols"
        return [self.scores[category], self.scored, missing]

    def domain_update(self, in_reports, out_reports, dnssec_row, dmarc_row, spf_row, mta_sts_row, tlsrpt_report, mecsa_st_dkim=None):
        """
        This class calculates the final score, given the results of the assessment.

        :param in_reports:  List of inbound_reports
        :param out_reports:  List of outbound_reports
        :param dnssec_row: Dictionary of values from the DNSSEc test.
        {}
        :param dmarc_row: Dictionary of values form the DMARC test.
        ()
        :param spf_row:Dictionary of values form the SPF test.
        {}
        :param mta_sts_row: Dictionary of values form the MTA-STS test.
        {}
        :param tlsrpt_report: Dictionary of values form the TLS-REPORT test.
        {}
        :param mecsa_st_dkim: DKIM test results for the command line version of the tests.
        {boolean, txt}
        :return: ----
        """
        starttls = 0
        ca_valid = 0
        fqdn_valid = 0
        date_valid = 0
        revocated = 0
        dane = 0
        mta_sts = 0
        try:
            values = init_domain_update()
            dnssec_support = dnssec_row['dd_dnssec']
            dnssec_txt = dnssec_row['dd_error']
            total_mx_starttls = 0
            total_mx = 0
            total_out = len(out_reports)
            for report in in_reports:
                # This test is to avoid counting MX connection errors as NO StartTLS support!
                if report['ir_smtp_success']:
                    total_mx += 1
                    starttls_support = False
                    cipher_support = False
                    tls_versions = ["TLSv1.2", "TLSv1.3"]
                    if report['ir_starttls']:
                        starttls_support = True
                        # enforcing the usage of NON-deprecated TLS
                        for tls_version in tls_versions:
                            if tls_version in report['ir_starttls_enc']:
                                cipher_support = True
                    if starttls_support and cipher_support:
                        total_mx_starttls += 1
                        starttls += 100
                        # Without StartTLS there's NO certificate.
                        if report['ir_certificate_ca_valid']:
                            ca_valid += 100
                        if report['ir_certificate_fqdn_valid']:
                            fqdn_valid += 100
                        if report['ir_certificate_date_valid']:
                            date_valid += 100
                        if not report['ir_certificate_revocated']:
                            revocated += 100
                    elif cipher_support is False:
                        self.logger.warning("StarTLS: TLS < 1.2 are deprecated! [{0}] ".format(report['ir_starttls_enc']))
                    if report['ir_tlsa']:
                        dane += 100
                    if report['ir_valid_mta_sts']:
                        mta_sts += 100

            if total_mx == 0:
                self.logger.warning("From  %d MX, ALL reported Connection Errors!!" % len(in_reports))

            for report in out_reports:
                if report['or_starttls']:
                    starttls += 100
                if report['or_dkim_valid']:
                    values['dr_dkim'] += 100
                if report['or_spf_valid']:
                    values['dr_spf'] += 100

            if (total_out == 0) and mecsa_st_dkim is not None:
                if mecsa_st_dkim[0]:
                    values['dr_dkim'] = 100

            if (total_mx + total_out) > 0:
                total_starttls = starttls / (total_mx + total_out)
            else:
                total_starttls = 0

            if total_mx > 0:
                total_dane = dane / total_mx
                total_mta_sts = mta_sts / total_mx
            else:
                total_dane = 0
                total_mta_sts = 0

            # The certificate percentage only applies to the number of MX with starttls.
            if total_mx_starttls > 0:
                total_certificate = (ca_valid + date_valid + fqdn_valid + revocated) / (4*total_mx_starttls)
            else:
                total_certificate = 0

            values['dr_starttls'] = total_starttls
            values['dr_certificate'] = total_certificate
            values['dr_mx_records'] = total_mx
            values['dr_out_records'] = total_out
            values['dr_dane'] = total_dane
            values['dr_mta_sts'] = total_mta_sts

            if total_out > 0:
                values['dr_dkim'] /= total_out
                # value corresponding to the fulfilment of SPF policies when delivering emails
                values['dr_spf'] /= total_out

            # value corresponding to the DNS record for SPF, DMARC and DNSSEC
            if spf_row['supports_spf']:
                values['dr_spf'] += 100
            # when used with MECSA, we have inbound and outbound SPF, with mecsa-st we only have inbound
            if mecsa_st_dkim is None:
                values['dr_spf'] /= 2
            values['dr_spf_txt'] = spf_row['spf_txt']
            values['dr_has_spf_record'] = spf_row['has_spf']
            values['dr_valid_spf_syntax'] = spf_row['spf_syntax_check']

            if dmarc_row['supports_dmarc']:
                values['dr_dmarc'] = 100
            values['dr_dmarc_txt'] = dmarc_row['dmarc_txt']
            values['dr_has_dmarc_record'] = dmarc_row['has_dmarc']
            values['dr_valid_dmarc_syntax'] = dmarc_row['dmarc_syntax_check']

            if dnssec_support is True:
                values['dr_dnssec'] = 100
            elif dnssec_support is False:
                values['dr_dnssec'] = 0
                values['dr_dnssec_txt'] = dnssec_txt

            # calculate the number of 'stars' for Confidentiality
            rules = self.summary_report(values, 'confidentiality', 'dr_confidential')
            if rules is False:
                self.logger.info('CONFIDENTIAL: none of the rules matched!')

            # calculate the number of 'stars' for Spoofing
            rules = self.summary_report(values, 'spoofing', 'dr_spoofing')
            if rules is False:
                self.logger.info('SPOOFING: none of the rules matched!')

            # calculate the number of 'stars' for Integrity
            rules = self.summary_report(values, 'integrity', 'dr_integrity')
            if rules is False:
                self.logger.info('INTEGRITY: none of the rules matched!')

            # Values from MTA-STS test
            values['has_mta_sts'] = mta_sts_row['has_mta_sts']
            values['has_mta_sts_dns'] = mta_sts_row['has_mta_sts_dns']
            values['mta_sts_dns_syntax'] = mta_sts_row['mta_sts_dns_syntax']
            values['mta_sts_dns'] = mta_sts_row['mta_sts_dns']
            values['has_mta_sts_policy'] = mta_sts_row['has_mta_sts_policy']
            values['mta_sts_policy_syntax'] = mta_sts_row['mta_sts_policy_syntax']
            values['mta_sts_policy'] = mta_sts_row['mta_sts_policy']
            values['mta_sts_error'] = mta_sts_row['mta_sts_error']

            return values
        except Exception as ex:
            self.logger.error("domain_update (%s)" % str(ex))
            return None

    def generate_score_string(self, score, raw_values):
        """
        It compares the list of protocols to evaluate with the results obtained in the assessment to generate the
        list of protocols supported.

        :param score: list of protocols to evaluate. This list depends on the category evaluated, i.e. confidentiality,
                      spoofing, or integrity.
        :param raw_values: result of the assessment.

        """
        try:
            score_string = []
            if 'starttls' in score and raw_values['dr_starttls'] >= 80:
                try:
                    score_string.append("starttls")
                    # without StartTLS there is not test for x509
                    if 'x509' in score and raw_values['dr_certificate'] >= 80:
                        score_string.append("x509")
                except Exception as starttls_score_ex:
                    self.logger.warning("StartTLS score failed ({0})".format(starttls_score_ex))                    
            if 'spf' in score and raw_values['dr_spf'] >= 80:
                try:
                    score_string.append("spf")
                    if 'spf_policy' in score:
                        spf_record = raw_values['dr_spf_txt'].lower()
                        if 'redirect=' in spf_record:
                            try:
                                self.logger.info("SPF policy is redirected!")
                                tester = test_spf.Spf(self.logger)
                                redirect_domain = spf_record.split("redirect=")[1].split()[0]
                                self.logger.info("----> spf redirection {0}".format(redirect_domain))
                                _, spf_record, _ = tester.fecth_spf(redirect_domain)                   
                                self.logger.info("----> new spf record  {0}".format(spf_record))
                                if '-all' in spf_record or ' ~all' in spf_record:
                                    score_string.append("spf_policy")                            
                            except Exception as spfex:
                                self.logger.warning("SPF redirection failed! {0} [{1}]".format(spf_record, spfex))
                        else:
                            if '-all' in spf_record or ' ~all' in spf_record:
                                score_string.append("spf_policy")
                except Exception as spf_score_ex:
                    self.logger.warning("SPF score failed ({0})".format(spf_score_ex))
            if 'dkim' in score and raw_values['dr_dkim'] >= 80:
                score_string.append("dkim")
            if 'dmarc' in score and raw_values['dr_dmarc'] >= 80:
                try:
                    score_string.append("dmarc")
                    if 'dmarc_policy' in score:
                        dmarc_parsed = raw_values['dr_dmarc_txt'].lower().split(";")
                        enforce_policy = False
                        enforce_reporting = False                  
                        for parsed in dmarc_parsed:
                            if 'p=reject' == parsed.strip() or 'p=quarantine' == parsed.strip():
                                enforce_policy = True
                            if 'rua=' in parsed.strip() or 'ruf=' in parsed.strip():
                                enforce_reporting = True
                        if enforce_policy and enforce_reporting:
                            score_string.append("dmarc_policy")
                except Exception as dmarc_score_ex:
                    self.logger.warning("DMARC score failed ({0})".format(dmarc_score_ex))
            if 'dane' in score and raw_values['dr_dane'] >= 80:
                score_string.append("dane")
            if 'dnssec' in score and raw_values['dr_dnssec'] >= 80:
                score_string.append("dnssec")
            if 'mta-sts' in score and raw_values['dr_mta_sts'] >= 80:
                score_string.append("mta-sts")
            return ",".join(score_string)
        except Exception as ex:
            self.logger.error(
                "ScoreOperations.generate_code_string %s (%s)" % (score, str(ex)))
            return ""

    def summary_report(self, values, summary_category, db_field):
        """
        formula to calculate the summary value for 'summary_category' (1 to 5).

        :param values: lore ipsum
        :param summary_category: lore ipsum
        :param db_field: lore ipsum
        :return: ----
        """
        score_string = "empty"
        try:
            score_string = self.generate_score_string(self.scores[summary_category], values)
            self.scored[summary_category] = score_string
            self.logger.info("Summary {0} protocols supported: {1}".format(summary_category, score_string))
            index = hashlib.sha1(score_string.encode()).hexdigest()
            if index in self.scores:
                self.logger.debug("Found coincidence in the scoring "
                                  "table for '%s' - %s %s" % (summary_category, score_string, str(self.scores[index])))
                values[db_field] = int(self.scores[index])
            else:
                self.logger.warning("Protocol combination not found in "
                                    "table '%s' for %s" % (summary_category, score_string))
                values[db_field] = 0
            return True
        except Exception as ex:
            self.logger.error(
                "Operations.summary_report %s - %s (%s)" % (summary_category, score_string, str(ex)))
            return False
