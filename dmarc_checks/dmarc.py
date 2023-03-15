'''
Copyright 2018 European Commission

Licensed under the EUPL, Version 1.2 or as soon they will be approved by the European
Commission - subsequent versions of the EUPL (the "Licence");

You may not use this work except in compliance with the Licence.

You may obtain a copy of the Licence at:

https://joinup.ec.europa.eu/software/page/eupl

Unless required by applicable law or agreed to in writing, software distributed under the Licence is distributed
on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

See the Licence for the specific language governing permissions and limitations under the Licence.
'''
__author__ = 'Joint Research Centre (JRC) - E.3 Cyber and Digital Citizen\'s Security'

import dns.resolver
import re

# DMARC standard: https://tools.ietf.org/html/rfc7489

EMAILREGEX = re.compile(r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)")


class Dmarc:

    def __init__(self, logger, tlds_list):
        self.logger = logger
        self.tlds_list = tlds_list

    def init_dmarc_parameters(self):
        '''
        Generates a Dictionary with all values obtained during the DMARC test.

        :return: Dictionary:
        supports_dmarc --------- Boolean, (has a DMARC record?) and (it is well formed (no syntax errors)?) True:False
        has_dmarc -------------- Boolean, does it have a DNS DMARC record (TXT type on _dmarc.<domain>)? True:False
        dmarc_record ----------- String, DMARC record
        dmarc_syntax_check ----- Boolean, is the DMARC record well formed? True:False
        dmarc_syntax_response -- String, error (if any) during the syntax check
        dmarc_error ------------ String, general error (if any) during the DMARC test
        '''
        dmarc_row = {}
        dmarc_row['supports_dmarc'] = False
        dmarc_row['has_dmarc'] = False
        dmarc_row['dmarc_record'] = None
        dmarc_row['dmarc_syntax_check'] = False
        dmarc_row['dmarc_syntax_response'] = None
        dmarc_row['dmarc_error'] = None
        return dmarc_row

    def test_dmarc(self, domain):
        '''
        Given a domain name 'domain', it will check if it has a DMARC record, and if this record is well formed.

        :param domain: String, domain name to test
        :return: dictionary of values 'init_dmarc_parameters' extracted from the DMARC record
        '''
        try:
            dmarc_errors = []
            row = self.init_dmarc_parameters()
            row['has_dmarc'], row['dmarc_record'], fetch_error = self.fetch_dmarc(domain)
            if row['has_dmarc']:
                row['dmarc_syntax_check'], row['dmarc_syntax_response'], syntax_error = self.check_dmarc_syntax(row['dmarc_record'])
                if syntax_error is not None:
                    dmarc_errors.append(syntax_error)
            else:
                dmarc_errors.append(fetch_error)
                org_domain, org_domain_error = self.find_organizational_domain(domain)
                if (org_domain is not None) and (org_domain != domain):
                    self.logger.warning("%s Organiztional Domain %s" % (domain, org_domain))
                    row['has_dmarc'], row['dmarc_record'], fetch_error = self.fetch_dmarc(org_domain)
                    if row['has_dmarc']:
                        row['dmarc_syntax_check'], row['dmarc_syntax_response'], syntax_error = self.check_dmarc_syntax(row['dmarc_record'])
                        if syntax_error is not None:
                            dmarc_errors.append(syntax_error)
                        row['dmarc_record'] += (" (From Organizational domain %s)" % org_domain)
                    else:
                        dmarc_errors.append(fetch_error)
                else:
                    if org_domain_error is not None:
                        dmarc_errors.append(org_domain_error)
            row['dmarc_error'] = "; ".join(dmarc_errors)
        except Exception as ex:
            exception_error = 'DMARC test Error %s (%s)' % (domain, str(ex))
            dmarc_errors.append(exception_error)
            row['dmarc_error'] = "; ".join(dmarc_errors)
            self.logger.warning(exception_error)
        return row

    def find_organizational_domain(self, domain):
        '''
        given a subdomain, it returns its organizatinal domain, if it has one.

        :param domain: String, subdomain from which to obtain the organizational domain
        :return: String - organizational domain of 'domain' if it has one, otherwise returns the same value.
                 String - error message
        '''
        try:
            if domain[-1] == '.':
                test_domain = domain[0:-1]
            else:
                test_domain = domain

            components = test_domain.split('.')
            c_length = len(components)

            index = 0
            org = '.'.join(components[index:c_length])

            while org not in self.tlds_list:
                if (index + 1) >= c_length:
                    return None, "Looking for organizational domain of %s (Index Out of Bounds! index+1)" % domain
                index += 1
                org = '.'.join(components[index:c_length])

            if index == 0:
                return org, None
            else:
                return '.'.join(components[(index - 1):c_length]), None
        except Exception as ex:
            return None, "Failed to find Organizational domain for %s (%s)" % (domain, str(ex))

    def fetch_dmarc(self, domain):
        '''
        This function returns the DMARC record of 'domain', if it has one.

        :param domain: String, domain name assessed.
        :return: Boolean - 'domain' has DMARC record? True:False
                 String  - DMARC record found
                 String  - Error found, if any
        '''
        try:
            dmarc_error = None
            records = 0
            dmarc_record = None
            has_dmarc = False
            dmarc_domain = '_dmarc.' + domain
            answers = dns.resolver.query(dmarc_domain, 'TXT')
            for answer in answers:
                record = ""
                for element in answer.strings:
                    record = record + str(element, "utf-8")
                if record.lower().startswith("v=dmarc1"):
                    if records < 1:
                        dmarc_record = record
                        has_dmarc = True
                        records += 1
                    else:
                        dmarc_record += ' ' + record
                        records += 1
                        has_dmarc = False
                        dmarc_error = 'Error: %d DMARC records found' % records
            if records == 0:
                dmarc_error = "Error: No valid DMARC record found."
            return has_dmarc, dmarc_record, dmarc_error
        except dns.resolver.NXDOMAIN:
            dmarc_error = '[DMARC] NXDOMAIN: %s' % dmarc_domain
            self.logger.warning(dmarc_error)
        except dns.resolver.Timeout:
            dmarc_error = '[DMARC] Timeout: %s' % dmarc_domain
            self.logger.warning(dmarc_error)
        except dns.resolver.NoAnswer:
            dmarc_error = '[DMARC] NoAnswer: %s' % dmarc_domain
            self.logger.warning(dmarc_error)
        except dns.exception.DNSException as dex:
            dmarc_error = '[DMARC] DNSException: %s (%s)' % (dmarc_domain, str(dex))
            self.logger.warning(dmarc_error)
        except Exception as ex:
            dmarc_error = '[DMARC] GENERAL Exception: %s (%s)' % (dmarc_domain, str(ex))
            self.logger.warning(dmarc_error)
        return False, None, dmarc_error

    def check_dmarc_report_uri(self, uri, tag):
        '''
        Checks if a URI (valid in rua and ruf tags) is valid
        URI takes the format of mailto:<email-address>[!<digits>[kmgt]]

        :param uri: uri to assess
        :param tag: complete rua/ruf tag
        :return: Boolean - valid URI? True:False
        '''
        if not uri.startswith("mailto:"):
            return False, "Unknown URI found in '%s' tag" % tag
        uri_value = uri[7:]
        parts = uri_value.split("!")
        if len(parts) > 2:
            return False, "Malformed URI in '%s' tag" % tag
        if not EMAILREGEX.match(parts[0]):
            return False, "Malformed email address in '%s' tag" % tag
        if len(parts) == 2:
            if len(parts[1]) == 0:
                return False, "Empty maximun size in '%s' tag" % tag
            if parts[1][-1].isdigit():
                size = parts[1]
            else:
                size = parts[1][:-1]
                if parts[1][-1] not in ["k", "m", "g", "t"]:
                    return False, "Malformed email address in '%s' tag" % tag
            if not size.isdigit():
                return False, "Malformed maximun size in '%s' tag" % tag
        return True, None

    def check_dmarc_syntax(self, raw_dmarc_str):
        '''
        Performs a syntax check on a DMARC TXT record string
        example record: v=DMARC1\; p=none\; rua=mailto:mailauth-reports@google.com

        :param raw_dmarc_str: String representing a DMARC record
        :return: Boolean - 'raw_dmarc_str' complies with DMARC Syntax? True:Falsee
                 String  - warning message
                 String  - error message
        '''
        VALID_TAGS = ["adkim", "aspf", "pct", "p", "rf", "ri", "rua", "ruf", "sp", "v"]
        dmarc_str = raw_dmarc_str.replace(' ', '')
        # Split in tag_value pairs, separated by ; and run sanity checks on the syntax
        tags = {}
        unknown_tag = False
        try:
            for tag_value in dmarc_str.split(";"):
                if len(tag_value) > 0:
                    parts = tag_value.split("=")
                    if len(parts) != 2:
                        dmarc_error = "Error parsing DMARC record: Invalid pair tag-value found (%s)" % dmarc_str
                        self.logger.warning(dmarc_error)
                        return False, None, dmarc_error
                    if parts[0] not in VALID_TAGS:
                        unknown_tag = True
                    if len(tags) == 0 and (parts[0] != "v" or parts[1] != "DMARC1"):
                        dmarc_error = "Error parsing DMARC record: First tag-value pair was not v=DMARC1 (%s)" % dmarc_str
                        self.logger.warning(dmarc_error)
                        return False, None, dmarc_error
                    if parts[0] in tags:
                        dmarc_error = "Error parsing DMARC record: Duplicated tag found (%s)" % dmarc_str
                        self.logger.warning(dmarc_error)
                        return False, None, dmarc_error
                    if len(parts[1]) == 0:
                        dmarc_error = "Error parsing DMARC record: Empty value found (%s)" % dmarc_str
                        self.logger.warning(dmarc_error)
                        return False, None, dmarc_error
                    tags[parts[0]] = parts[1]
        except Exception as ex:
            dmarc_error = "Error parsing DMARC record: %s (%s)" % (dmarc_str, str(ex))
            self.logger.error(dmarc_error)
            return False, None, dmarc_error

        # Run specific sanity checks on each tag value
        try:
            for tag in tags:
                value = tags[tag]
                # "DEBUG: Testing syntax for DMARC tag pair: %s - %s" %(tag, value)
                if tag == "adkim" and value not in ["r", "s"]:
                    dmarc_error = "Error in Sanity Check DMARC record: Unknown value for 'adkim' tag (%s)" % dmarc_str
                    self.logger.warning(dmarc_error)
                    return False, None, dmarc_error
                elif tag == "aspf" and value not in ["r", "s"]:
                    dmarc_error = "Error in Sanity Check DMARC record: Unknown value for 'aspf' tag (%s)" % dmarc_str
                    self.logger.warning(dmarc_error)
                    return False, None, dmarc_error
                elif tag == "fo":
                    parts = value.split(":")
                    for part in parts:
                        if part not in ["0", "1", "d", "s"]:
                            dmarc_error = "Error in Sanity Check DMARC record: Unknown value for 'fo' tag (%s)" % dmarc_str
                            self.logger.warning(dmarc_error)
                            return False, None, dmarc_error
                elif tag == "p" and value not in ["none", "quarantine", "reject"]:
                    dmarc_error = "Error in Sanity Check DMARC record: Unknown value for 'p' tag (%s)" % dmarc_str
                    self.logger.warning(dmarc_error)
                    return False, None, dmarc_error
                elif tag == "pct":
                    if not value.isdigit():
                        dmarc_error = "Error in Sanity Check DMARC record: Value for 'pct' tag is not an integer (%s)" % dmarc_str
                        self.logger.warning(dmarc_error)
                        return False, None, dmarc_error
                    if int(value) > 100:
                        dmarc_error = "Error in Sanity Check DMARC record: Value for 'pct' is not in range 0-100 (%s)" % dmarc_str
                        self.logger.warning(dmarc_error)
                        return False, None, dmarc_error
                elif tag == "rf":
                    # TODO: to be implemented
                    pass
                elif tag == "ri" and not value.isdigit():
                    dmarc_error = "Error in Sanity Check DMARC record: Value for 'ri' tag is not an integer (%s)" % dmarc_str
                    self.logger.warning(dmarc_error)
                    return False, None, dmarc_error
                elif tag == "rua":
                    for uri in value.split(","):
                        res, res_str = self.check_dmarc_report_uri(uri, tag)
                        if not res:
                            dmarc_error = "Error in Sanity Check DMARC record: (%s, %s)" % (res_str, dmarc_str)
                            self.logger.warning(dmarc_error)
                            return False, None, dmarc_error
                elif tag == "ruf":
                    for uri in value.split(","):
                        res, res_str = self.check_dmarc_report_uri (uri, tag)
                        if not res:
                            dmarc_error = "Error in Sanity Check DMARC record: (%s, %s)" % (res_str, dmarc_str)
                            self.logger.warning(dmarc_error)
                            return False, None, dmarc_error
                elif tag == "sp" and value not in ["none", "quarantine", "reject"]:
                    dmarc_error = "Error in Sanity Check DMARC record: Unknown value for 'sp' tag (%s)" % dmarc_str
                    self.logger.error(dmarc_error)
                    return False, None, dmarc_error
        except Exception as ex:
            dmarc_error = "Error in Sanity Check DMARC record: %s (%s)" % (str(ex), dmarc_str)
            self.logger.error(dmarc_error)
            return False, None, dmarc_error

        if unknown_tag:
            return True, "Dmarc syntax OK (Unknown Tag Found!)", None
        else:
            return True, "Dmarc syntax OK", None
