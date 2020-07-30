
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

    def __init__(self, logger):
        self.logger = logger

    def domain_update(self, in_reports, out_reports, dnssec_row, dmarc_row, spf_row, mta_sts_row, mecsa_st_dkim=None):
        '''
        This class updates the scores in the domain_request table.
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
        :param mecsa_st_dkim: DKIM test results for the command line version of the tests.
        {boolean, txt}
        :return: ----
        '''
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
                    if report['ir_starttls']:
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
                    if report['ir_tlsa']:
                        dane += 100
                    if report['ir_valid_mta_sts']:
                        mta_sts += 100

            if total_mx == 0:
                self.logger.warning("From " + str(len(in_reports)) + " MX, ALL reported Connection Errors!!")

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
            # when used with MECSA, we have inbound and outbound SPF
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

            # claculate the number of 'stars' for Confidential
            rules = self.summary_report_confidential(values)
            if rules is False:
                self.logger.info('CONFIDENTIAL: none of the rules matched!')

            # claculate the number of 'stars' for Spoofing
            rules = self.summary_report_spoofing(values)
            if rules is False:
                self.logger.info('SPOOFING: none of the rules matched!')

            # claculate the number of 'stars' for Spoofing
            rules = self.summary_report_integrity(values)
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

            # update the domain_request table with the results
            # self.dbops.domain_request_update(values, spf_row, dmarc_row, row_mta_sts, self.pk)
            return values
        except Exception as ex:
            self.logger.error("domain_update " + str(ex))
            return None

    def summary_report_confidential(self, values):
        '''
        formula to calculate the summary value for CONFIDENTIALITY (1 to 5).
        smtp-sts does not have any effect, it is not a standard yet.
        TODO: rate from 1 to 10; define the final rule.
        '''
        try:
            # we calculate the inputs as '0' (false) or '1' true.
            if values['dr_starttls'] >= 80:
                starttls = True
            else:
                starttls = False
            if values['dr_certificate'] >= 80:
                v509 = True
            else:
                v509 = False
            if values['dr_dane'] >= 80:
                dane = True
            else:
                dane = False
            if values['dr_dnssec'] >= 80:
                dnssec = True
            else:
                dnssec = False
            if values['dr_mta_sts'] >= 80:
                mta_sts = True
            else:
                mta_sts = False

            # we calculate the CONFIDENTIALITY:
            if starttls is False:
                return True

            if (starttls and dane and dnssec) is True:
                values['dr_confidential'] = 10
                return True
            elif (starttls and v509 and mta_sts) is True:
                values['dr_confidential'] = 10
                return True

            if (starttls and v509 and dnssec) is True:
                values['dr_confidential'] = 8
                return True

            if (starttls and v509) is True:
                values['dr_confidential'] = 7
                return True

            elif (starttls and mta_sts) is True:
                values['dr_confidential'] = 7
                return True

            if (starttls and dnssec) is True:
                values['dr_confidential'] = 6
                return True

            if (starttls and dane) is True:
                values['dr_confidential'] = 6
                return True

            if starttls is True:
                values['dr_confidential'] = 5
                return True
            # false means no match with our rules.
            return False
        except Exception as ex:
            self.logger.error(
                "Operations.summary_report_confidential " + str(ex))

    def summary_report_spoofing(self, values):
        '''
        formula to calculate the summary value for SPOOFING (1 to 5).
        DMARC does not have any effect, TODO: rate from 1 to 10
        to account for DMARC.
        TODO: define the final rule
        '''
        try:
            # we calculate the inputs as '0' (false) or '1' true.
            if values['dr_spf'] >= 80:
                spf = True
                if ' -all' in values['dr_spf_txt'].lower() or ' ~all' in values['dr_spf_txt'].lower():
                    spf_policy = True
                else:
                    spf_policy = False
            else:
                spf = False
                spf_policy = False
            if values['dr_dkim'] >= 80:
                dkim = True
            else:
                dkim = False
            if values['dr_dmarc'] >= 80:
                dmarc = True
                if 'p=reject' in values['dr_dmarc_txt'].lower() or 'p=quarantine' in values['dr_dmarc_txt'].lower():
                    dmarc_policy = True
                else:
                    dmarc_policy = False
            else:
                dmarc = False
                dmarc_policy = False
            if values['dr_dnssec'] >= 80:
                dnssec = True
            else:
                dnssec = False

            # if (spf or dkim) is False:
            #     return True

            # we calculate the SPOOFING:

            if (spf and dkim and dmarc and dnssec) is True:
                if (spf_policy and dmarc_policy) is True:
                    values['dr_spoofing'] = 10
                elif dmarc_policy is True:
                    values['dr_spoofing'] = 9
                elif spf_policy is True:
                    values['dr_spoofing'] = 9
                else:
                    values['dr_spoofing'] = 8
                return True

            if (dkim and dmarc and dnssec) is True:
                if dmarc_policy:
                    values['dr_spoofing'] = 8
                else:
                    values['dr_spoofing'] = 7
                return True

            if (spf and dmarc and dnssec) is True:
                if dmarc_policy is True:
                    values['dr_spoofing'] = 8
                elif spf_policy is True:
                    values['dr_spoofing'] = 7
                else:
                    values['dr_spoofing'] = 6
                return True

            if (spf and dkim and dnssec) is True:
                if spf_policy is True:
                    values['dr_spoofing'] = 8
                else:
                    values['dr_spoofing'] = 6
                return True

            if (spf and dnssec) is True:
                if spf_policy is True:
                    values['dr_spoofing'] = 6
                else:
                    values['dr_spoofing'] = 4
                return True

            if (dkim and dnssec) is True:
                values['dr_spoofing'] = 5
                return True

            if (dmarc and dnssec) is True:
                if dmarc_policy is True:
                    values['dr_spoofing'] = 4
                else:
                    values['dr_spoofing'] = 3
                return True

            if (spf and dkim and dmarc) is True:
                if (spf_policy and dmarc_policy) is True:
                    values['dr_spoofing'] = 8
                elif dmarc_policy is True:
                    values['dr_spoofing'] = 7
                elif spf_policy is True:
                    values['dr_spoofing'] = 7
                else:
                    values['dr_spoofing'] = 6
                return True

            if (spf and dkim) is True:
                if spf_policy is True:
                    values['dr_spoofing'] = 7
                else:
                    values['dr_spoofing'] = 5
                return True

            if (spf and dmarc) is True:
                if dmarc_policy is True:
                    values['dr_spoofing'] = 6
                elif spf_policy is True:
                    values['dr_spoofing'] = 6
                else:
                    values['dr_spoofing'] = 5
                return True

            if (dkim and dmarc) is True:
                if dmarc_policy is True:
                    values['dr_spoofing'] = 6
                else:
                    values['dr_spoofing'] = 5
                return True

            if spf is True:
                if spf_policy is True:
                    values['dr_spoofing'] = 6
                else:
                    values['dr_spoofing'] = 5
                return True

            if dkim is True:
                values['dr_spoofing'] = 5
                return True

            if dmarc is True:
                values['dr_spoofing'] = 4
                return True

            if spf is False  and dkim is False  and dmarc is False:
                values['dr_spoofing'] = 0
                return True
            # false means no match with our rules.
            return False
        except Exception as ex:
            self.logger.error(
                "Operations.summary_report_spoofing " + str(ex))

    def summary_report_integrity(self, values):
        '''
        formula to calculate the summary value for INTEGRITY (1 to 5).
        TBD: do we need TLS when receiveing and delivering both?.
        TODO: define the final rules!
        '''
        try:
            # we calculate the inputs as '0' (false) or '1' true.
            if values['dr_starttls'] >= 80:
                starttls = True
            else:
                starttls = False
            if values['dr_certificate'] >= 80:
                x509 = True
            else:
                x509 = False
            if values['dr_dnssec'] >= 80:
                dnssec = True
            else:
                dnssec = False
            if values['dr_dkim'] >= 80:
                dkim = True
            else:
                dkim = False
            if values['dr_dmarc'] >= 80:
                dmarc = True
                if 'p=reject' in values['dr_dmarc_txt'].lower() or 'p=quarantine' in values['dr_dmarc_txt'].lower():
                    dmarc_policy = True
                else:
                    dmarc_policy = False
            else:
                dmarc = False
                dmarc_policy = False

            # we calculate the INTEGRITY value:
            if (not starttls and not dkim and not dmarc) is True:
                return True

            if (dkim and dmarc and dnssec) is True:
                if dmarc_policy:
                    values['dr_integrity'] = 10
                else:
                    values['dr_integrity'] = 8
                return True

            if dkim and dnssec:
                values['dr_integrity'] = 8
                return True

            if (dkim and dmarc) is True:
                if dmarc_policy:
                    values['dr_integrity'] = 7
                else:
                    values['dr_integrity'] = 6
                return True

            if (starttls and x509) is True:
                values['dr_integrity'] = 5
                return True

            if starttls is True:
                values['dr_integrity'] = 4
                return True

            if (dmarc and dnssec) is True:
                values['dr_integrity'] = 4
                return True

            if (dmarc or dnssec) is True:
                values['dr_integrity'] = 2
                return True

            # false means no match with our rules.
            return False
        except Exception as ex:
            self.logger.error(
                "Operations.summary_report_integrity " + str(ex))
