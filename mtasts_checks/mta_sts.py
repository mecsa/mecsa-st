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

import requests
import dns.resolver

__default_ns__ = '1.1.1.1'


class MtaSts(object):

    def __init__(self, logger):
        self.logger = logger

    def init_mta_sts_parameters(self):
        """
        Initializes the dictionary used in the MTA-STS assessment.

        :return: Dictionary,
        has_mta_sts ---------------- Boolean, MTA-STS is supported
        has_mta_sts_dns ---------Boolean, has MTA-STS DNS record? True:False
        mta_sts_dns_syntax ----- Boolean, MTA-STS DNS record passed syntax check? True:False
        mta_sts_dns ------------ String, MTA-STS DNS record
        has_mta_sts_policy ----- Boolean, has MTA-STS policy? True:False
        mta_sts_policy_syntax -- Boolean, MTA-STS policy passed syntax check? True:False
        mta_sts_policy --------- String, MTA-STS policy
        mta_sts_error ---------- String, error (if any)

        """
        mta_sts_row = {}
        mta_sts_row['has_mta_sts'] = False
        mta_sts_row['has_mta_sts_dns'] = False
        mta_sts_row['mta_sts_dns_syntax'] = False
        mta_sts_row['mta_sts_dns'] = None
        mta_sts_row['has_mta_sts_policy'] = False
        mta_sts_row['mta_sts_policy_syntax'] = False
        mta_sts_row['mta_sts_policy'] = None
        mta_sts_row['mta_sts_error'] = None
        return mta_sts_row

    def check_dns_syntax(self, dns_mtasts):
        """
        Given an MTA-STS DNS record, it will check its syntax.

        :param dns_mtasts: String, the DNS record to test
        :return:  Boolean, MTA-STS DNS syntax OK? True:False
                  String, if failed, description of the syntax error.
        """
        try:
            self.logger.debug("DNS-MTA-STS-SYNTAX-CHECK: %s " % dns_mtasts)
            if dns_mtasts[-1] == ";":
                keywords = dns_mtasts[:-1].split(";")
            else:
                keywords = dns_mtasts.split(";")
            for keyword in keywords:
                payload = keyword.split("=")[1]
                if "v=" in keyword and payload.lower() != "stsv1":
                    return False, "ERROR validating DNS MTA-STS id parameter should be STSv1 (%s)" % payload
                elif "id=" in keyword and len(payload) > 32:
                    return False, "ERROR validating DNS MTA-STS v parameter  larger than 32 (%s)" % payload
            return True, None
        except Exception as error:
            self.logger.error("DNS-MTA-STS Syntax-Error %s (%s)" % (str(dns_mtasts), str(error)))
            return False, "DNS-MTA-STS Syntax-Error " + str(error)

    def check_policy_syntax(self, policy_mtasts, dns_mtasts):
        """
        Given an MTA-STS POLICY record, it will check its syntax.

        :param policy_mtasts: String[], the POLICY record to test
        :param dns_mtasts: MTA-STS DNS registry
        :return:  Boolean, MTA-STS POLICY syntax OK? True:False
                  String, if failed, description of the syntax error.
        """
        try:
            self.logger.debug("POLICY-MTA-STS-SYNTAX-CHECK: %s (%s)" % (policy_mtasts, dns_mtasts))
            if policy_mtasts['version'].lower() != 'stsv1':
                syntax_error = "[MTA-STS] Error in policy syntax: wrong version value (%s)" % policy_mtasts['version']
                return False, syntax_error
            if policy_mtasts['mode'] is None:
                syntax_error = "[MTA-STS] Error in policy syntax: mode cannot be empty"
                return False, syntax_error
            elif policy_mtasts['mode'] not in ['none', 'testing', 'enforce']:
                syntax_error = "[MTA-STS] Error in policy syntax: mode %s is not valid" % policy_mtasts['mode']
                return False, syntax_error
            if policy_mtasts['max_age'] is None:
                syntax_error = "[MTA-STS] Error in policy syntax: max_age cannot be empty"
                return False, syntax_error
            if policy_mtasts['mx'] is None and policy_mtasts['mode'] != "none":
                syntax_error = "[MTA-STS] Error in policy syntax: MX cannot be empty with mode %s" % policy_mtasts['mode']
                return False, syntax_error
            return True, None
        except Exception as error:
            self.logger.error("POLICY-MTA-STS Syntax-Error %s (%s)" % (str(policy_mtasts), str(error)))
            return False, "POLICY-MTA-STS Syntax-Error " + str(error)

    def test_mta_sts(self, domain):
        """
        Given a domain:
            1.- It will fetch the MTA-STS DNS record
            2.- IF the record exists, it will check the syntax
            3.- IF MTA-STS DNS and Syntax, it will fetch the policy
            4.- IF policy exists, it will check the syntax
            5.- IF Policy and Syntax -> Domain has MTA-STS
        :param domain: Domain name tested.
        :return      : Boolean,

                        String, if True, it will return the SPF record. If False, it will return the corresponding error
        """
        row = self.init_mta_sts_parameters()
        try:
            # Fetching DNS record
            row['has_mta_sts_dns'], row['mta_sts_dns'], row['mta_sts_error'] = self.fetch_mta_sts_dns(domain)
            if row['has_mta_sts_dns']:
                # Checking DNS Syntax
                row['mta_sts_dns_syntax'], row['mta_sts_error'] = self.check_dns_syntax(row['mta_sts_dns'])
                if row['mta_sts_dns_syntax']:
                    # Fetching HTTPS Policy
                    row['has_mta_sts_policy'], row['mta_sts_policy'], row['mta_sts_error'] = self.fetch_mta_sts_policy(domain)
                    if row['has_mta_sts_policy']:
                        # Checking policy Syntax
                        row['mta_sts_policy_syntax'], row['mta_sts_error'] = self.check_policy_syntax(row['mta_sts_policy'], row['mta_sts_dns'])
                        if row['mta_sts_policy_syntax']:
                            row['has_mta_sts'] = True
        except Exception as ex:
            row['mta_sts_error'] = "MTA-STS-Test Generic Error %s (%s)" % (domain, str(ex))
            self.logger.error(row['mta_sts_error'])
        return row

    def fetch_mta_sts_dns(self, domain, name_servers=None):
        """
        Given a domain, it will fetch its MTA-STS DNS record, if it exists.
        :param domain:  Domain name tested
        :param name_servers: optional, list of ip addresses to use as name server
        :return: Boolean, domain has SPF record? True:False
                 String, TXT records found
                 String, Errors (if any) in the query
        """

        mta_sts_domain = "_mta-sts." + domain
        try:
            records = 0
            if name_servers is None:
                name_servers = [__default_ns__]
            mta_sts_error = None
            has_mta_sts_dns = False
            mta_sts_record = None
            self.logger.debug("sending DNS TXT request for domain %s" % mta_sts_domain)
            resolver = dns.resolver.Resolver()
            resolver.nameservers = name_servers
            answers = resolver.query(mta_sts_domain, 'TXT')
            for answer in answers:
                record = ""
                for element in answer.strings:
                    record += str(element, "utf-8")
                if record.lower().startswith("v=stsv1"):
                    if records < 1:
                        mta_sts_record = record
                        has_mta_sts_dns = True
                        records += 1
                    else:
                        mta_sts_record += ' ' + record
                        records += 1
                        has_mta_sts_dns = False
                        mta_sts_error = 'Error: %d MTA-STS records found' % records
            if records == 0:
                mta_sts_error = "Error: No valid MTA-STS record found."
            return has_mta_sts_dns, mta_sts_record, mta_sts_error
        except dns.resolver.NXDOMAIN:
            mta_sts_error = '[MTA-STS] NXDOMAIN: %s' % mta_sts_domain
        except dns.resolver.Timeout:
            mta_sts_error = '[MTA-STS] Timeout: %s' % mta_sts_domain
        except dns.resolver.NoAnswer:
            mta_sts_error = '[MTA-STS] NoAnswer: %s' % mta_sts_domain
        except dns.exception.DNSException as dex:
            mta_sts_error = '[MTA-STS] DNSException: %s (%s)' % (mta_sts_domain, str(dex))
        except Exception as ex:
            mta_sts_error = '[MTA-STS] General Exception (%s)' % str(ex)
        self.logger.warning(mta_sts_error)
        return False, None, mta_sts_error

    def fetch_mta_sts_policy(self, domain):
        """
        Given a domain, it will fetch its MTA-STS DNS record, if it exists.
        :param domain:  Domain name tested
        :return: Boolean, domain has SPF record? True:False
                 String, TXT records found
                 String, Errors (if any) in the query
        """

        mta_sts_domain = "mta-sts.%s/.well-known/mta-sts.txt" % domain
        try:
            mta_sts_error = None
            self.logger.debug("sending POLICY request for domain %s " % mta_sts_domain)
            response = requests.get("https://" + mta_sts_domain)
            has_policy, parsed_result = self.parse_policy(response.text.splitlines())
            headers = response.headers
            self.logger.debug("Content/Type: %s" % headers['Content-Type'])
            self.logger.debug("request POLICY response:  %s " % parsed_result)
            if has_policy:
                return True, parsed_result, mta_sts_error
            else:
                mta_sts_error = parsed_result
        except Exception as ex:
            mta_sts_error = '[MTA-STS] General Exception %s (%s)' % (domain, str(ex))
        self.logger.warning(mta_sts_error)
        return False, None, mta_sts_error

    def parse_policy(self, policy):
        """

        :param policy: String List, each line of the policy content
        :return: dictionary, pair of key-value of the policy, if any.
        """
        try:
            has_mx = False
            mxs = []
            parsed_policy = {}
            parsed_policy['version'] = None
            parsed_policy['mode'] = None
            parsed_policy['mx'] = None
            parsed_policy['max_age'] = None
            parsed_policy['error'] = None
            for line in policy:
                if ':' in line:
                    key, value = line.strip().split(":")
                    self.logger.debug("KEY: %s; VALUE: %s" % (key, value))
                    if key == 'version' and parsed_policy['version'] is None:
                        parsed_policy['version'] = value.strip()
                    elif key == 'mode' and parsed_policy['mode'] is None:
                        parsed_policy['mode'] = value.strip()
                    elif key == 'mx':
                        has_mx = True
                        mxs.append(value.strip())
                    elif key == 'max_age' and parsed_policy['max_age'] is None:
                        parsed_policy['max_age'] = value.strip()
                else:
                    self.logger.warning("[MTA-STS] Parsing Policy Unknown line found: '%s' " % str(line))
                    return False, "Parsing Policy, Unknown line found: '%s' " % str(line)
            if has_mx:
                parsed_policy['mx'] = ",".join(mxs)
            return True, parsed_policy
        except Exception as ex:
            parsed_policy['error'] = "%s (%s)" % (str(policy), str(ex))
            self.logger.error("[MTA-STS] Error parsing policy %s " % parsed_policy['error'])
        return False, parsed_policy['error']

    def validate_policy(self, policy, mxs):
        """
        Given an MTA-STS policy, it will check if each MX complies with it.
        i.e. it will check if the MX hostname matches any of the mx that appear in the policy
        :param policy: MTA-STS policy obtained
        :param mxs: report dictionary, (see mecsa-st.init_report function)
        :return: -
        """
        try:
            trusted_mxs = policy['mx'].lower().split(",")
            for mx in mxs:
                candidate = mx['ir_mx'].lower()
                for trusted_mx in trusted_mxs:
                    try:
                        if mx['ir_valid_mta_sts'] is False:
                            self.logger.debug("[MTA-STS] Testing if MX %s matches Policy %s" % (candidate, trusted_mx))
                            mx['ir_mta_sts_txt'] = "mode:%s;mx:%s" % (policy['mode'], policy['mx'])
                            if trusted_mx[0] != '*':
                                mx['ir_valid_mta_sts'] = (candidate == trusted_mx)
                                self.logger.debug('[MTA-STS] Exact MATCH!: %s - %s' % (candidate, trusted_mx))
                            else:
                                mx['ir_valid_mta_sts'] = self.test_wildcard(candidate, trusted_mx)
                    except Exception as ex:
                        mta_sts_error = "[MTA-STS] " \
                                        "Error validating policy for " \
                                        "candidate %s with policy_mx %s (%s)" % (candidate, trusted_mx, str(ex))
                        mx['ir_mta_sts_errors'] = mta_sts_error
                        self.logger.error(mta_sts_error)
        except Exception as ex:
            mta_sts_error = "[MTA-STS] General Error validating policy (%s) (%s)" % (str(policy), str(ex))
            self.logger.error(mta_sts_error)

    def test_wildcard(self, candidate, wildcard):
        """
        It will check if an mx hostname (candidate) matches a wildcard mx
        :param candidate: mx hostname
        :param wildcard: wildcard hostname
        :return: Does the candidate matches the wildcard? True:False
        """
        try:
            self.logger.debug("[MTA-STS] wildcard")
            hostname = candidate
            tests = len(hostname.split('.'))
            for index in range(1, tests):
                sample = '*' + hostname[hostname.index('.'):]
                hostname = sample[2:]
                if sample == wildcard:
                    self.logger.debug('[MTA-STS] Wildcard MATCH!: %s - %s' % (sample, wildcard))
                    return True
        except Exception as ex:
            self.logger.debug("[MTA-STS] mx %s failed wildcard test %s (%s)" % (candidate, wildcard, str(ex)))
        return False
