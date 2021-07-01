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
from abnf.grammars import rfc5234
from abnf import ParseError, GrammarError

MAILREGEX = re.compile(r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)")
# URI regex from rfc3986
URIREGEX = re.compile(r"^(([^:/?#]+):)?(//([^/?#]*))?([^?#]*)(\?([^#]*))?(#(.*))?")

class Tlsrpt(object):

    def __init__(self, logger):
        self.logger = logger

    def init_tlsrpt_parameters(self):
        '''
        Initializes the dictionary used in the TLS RPT assessment.

        :return: Dictionary,

        has_tlsrpt -------------- Boolean, has TLS RPT record? True:False
        tlsrpt_record ----------- String, TLS RPT record
        tlsrpt_syntax_check ----- Boolean, TLS RPT record passed syntax check? True:False
        tlsrpt_syntax_response -- String, Response to the syntax check test
        tlsrpt_error ------------ String, error (if any)

        '''
        tlsrpt_row = {}
        tlsrpt_row['has_tlsrpt'] = False
        tlsrpt_row['tlsrpt_record'] = None
        tlsrpt_row['tlsrpt_syntax_check'] = None
        tlsrpt_row['tlsrpt_syntax_response'] = None
        tlsrpt_row['tlsrpt_error'] = None
        return tlsrpt_row

    def check_extension_syntax(self, extension_record):
        '''
        Checks the syntax of TLS RPT extensions. An extension comprises a name-value
        pair and its syntax is checked against the ABNF grammar defined in RFC 8460. 

        :param extension_record: String, the extension name-value pair to be checked
        :return:  Boolean, TLS RPT extension syntax OK? True:False
                  String, if failed, description of the error.
        '''
        try:
            if "=" in extension_record: 
                tlsrpt_extension = extension_record.split("=")
                if len(tlsrpt_extension) == 2:
                    tlsrpt_ext_name = tlsrpt_extension[0]
                    tlsrpt_ext_value = tlsrpt_extension[1]

                    name_rule = rfc5234.Rule.create('tlsrpt-ext-name-rule = (ALPHA / DIGIT) *31(ALPHA /\
                                                                            DIGIT / "_" / "-" / ".")')
                    value_rule = rfc5234.Rule.create('tlsrpt-ext-value-rule = 1*(%x21-3A / %x3C / %x3E-7E)')

                    name_rule.parse_all(tlsrpt_ext_name)
                    value_rule.parse_all(tlsrpt_ext_value)
                else:
                    return False, "TLS RPT-Text Syntax-Error: Malformed extension record (accepted syntax: <name>=<value>)"
            else:
                return False, f"TLS RPT-Text Syntax-Error: Malformed extension for record {extension_record} (accepted syntax: <name>=<value>)"
        except GrammarError as gerror:
            self.logger.warning(f"TLS RPT-Text GrammarError ({gerror})")
            return False, f"TLS RPT-Text GrammarError ({gerror})"
        except ParseError as perror:
            self.logger.warning(f"TLS RPT-Text ParseError ({perror})")
            return False, f"TLS RPT-Text ParseError ({perror})"
        except Exception as error:
            self.logger.warning(f"TLS RPT-Text General error ({error})")
            return False, f"TLS RPT-Text General error ({error})"
        return True, ""

    def check_rua_syntax(self, rua_record):
        '''
        Aggregate Report URI (rua) is a comma-separated list of URI locations
        where the report is to be submitted. The supported URI schemes are:
        "mailto" and "https". This function will check that a rua list contains
        a series of syntactically correct URIs, according to RFC 3986.

        :param rua_record: String, the rua list to test
        :return:  Boolean, URIs syntax in rua list OK? True:False
                  String, if failed, description of the error, otherwise None.
        '''
        try:
            record = rua_record.split("=")

            if len(record) == 2:
                uris = record[1].split(",")

                for uriwithspaces in uris:
                    uri = uriwithspaces.strip()
                    if uri.startswith("mailto"):
                        mail_addr = uri.split(":")[1]
                        if not MAILREGEX.match(mail_addr):
                            return False, "Malformed mailto URI in TLS RPT record: " + uri
                    elif uri.startswith("https"):
                        if not URIREGEX.match(uri):
                            return False, "Malformed https URI in TLS RPT record: " + uri
                    else:
                        return False, "Unsupported URI scheme in TLS RPT record (valid schemes are mailto and https): " + uri
            else:
                return False, "Malformed URI in TLS RPT record (more than 1 \"=\"): " + rua_record
        except Exception as error:
            return False, f"TLS-RPT Rua record check - General error ({error}) "

        return True, ""

    def check_syntax_tlsrpt(self, tlsrpt_text, domain):
        '''
        Given an TLS RPT record, it will check its syntax according to RFC 8460.
        In previous steps it has already been checked that the record starts 
        with v=TLSRPTv1 and that there is only one record.

        :param tlsrpt_text: String, the TLS RPT record to test
        :param domain: String, domain name tested
        :return:  Boolean, TLS RPT syntax OK? True:False
                  String, if failed, description of the syntax error.
        '''
        try:
            check_result, error_description = (None, None)

            parts = tlsrpt_text.split(";")

            # Check whether the TLS RPT record starts with a non-space character
            tlsrpt_version = parts[0]
            if not tlsrpt_version.startswith(" "):
                if tlsrpt_version.lower().rstrip() == "v=tlsrptv1":
                    for i in range(1, len(parts)):
                        part = parts[i].strip()
                        if part != "":
                            # Aggregate Report URI (rua)
                            if part.startswith("rua="):
                                check_result, error_description = self.check_rua_syntax(part)
                                if not check_result:
                                    return check_result, error_description
                            # Extension    
                            else:
                                check_result, error_description = self.check_extension_syntax(part)
                                if not check_result:
                                    return check_result, error_description
                else:
                    check_result, error_description = False, "TLS RPT record must start with v=TLSRPTv1"
                    return check_result, error_description
            else:
                check_result, error_description = False, "TLS RPT record cannot start with whitespace"
                return check_result, error_description
        except Exception as error:
            self.logger.error(f"TLS RPT-Text Syntax-Error {tlsrpt_text} ({error})")
            return False, f"TLS RPT-Text Syntax-Error {tlsrpt_text}"

        return check_result, error_description

    def test_tlsrpt(self, domain):
        '''
        Given a domain, it will fetch its TLS RPT record and check its syntax.

        :param domain: Domain name tested.
        :return: Dictionary, the dictionary used in the TLS RPT assessment 

        '''
        row = self.init_tlsrpt_parameters()
        try:
            row['has_tlsrpt'], row['tlsrpt_record'], row['tlsrpt_error'] = self.fecth_tlsrpt(domain)
            if row['has_tlsrpt']:
                row['tlsrpt_syntax_check'], description = self.check_syntax_tlsrpt(row['tlsrpt_record'], domain)
                if not row['tlsrpt_syntax_check']:
                    row['tlsrpt_error'] = description
        except Exception as ex:
            row['tlsrpt_error'] = "TLS RPT-Test Generic Error %s (%s)" % (str(domain), str(ex))
            self.logger.error(row['tlsrpt_error'])
        return row

    def fecth_tlsrpt(self, domain):
        '''
        Given a domain, it will return the TLS RPT record, if it has one.

        :param domain: Domain name tested
        :return: Boolean, domain has TLS RPT record? True:False
                 String, TLS RPT record
                 String, if failed, description of the error
        '''
        try:
            records = 0
            tlsrpt_error = None
            has_tlsrpt = False
            tlsrpt_record = None
            self.logger.debug(f'sending DNS TXT request for domain {domain}')

            resolver_query = f'_smtp._tls.{domain}'

            answers = dns.resolver.query(resolver_query, 'TXT')
            
            for answer in answers:
                record = ""
                for element in answer.strings:
                    record = record + str(element, "utf-8")
                if record.lower().startswith("v=tlsrptv1"):
                    if records < 1:
                        tlsrpt_record = record
                        has_tlsrpt = True
                        records += 1
                    else:
                        tlsrpt_record += ' ' + record
                        records += 1
                        has_tlsrpt = False
                        tlsrpt_error = f'Error: {records} TLS RPT records found'
            
            if records == 0:
                tlsrpt_error = "Error: No valid TLS RPT record found."
            return has_tlsrpt, tlsrpt_record, tlsrpt_error
        except dns.resolver.NXDOMAIN:
            tlsrpt_error = f'[TLS RPT] NXDOMAIN: {domain}'
            self.logger.warning(tlsrpt_error)
        except dns.resolver.Timeout:
            tlsrpt_error = f'[TLS RPT] Timeout: {domain}'
            self.logger.warning(tlsrpt_error)
        except dns.resolver.NoAnswer:
            tlsrpt_error = f'[TLS RPT] NoAnswer: {domain}'
            self.logger.warning(tlsrpt_error)
        except dns.exception.DNSException as dex:
            tlsrpt_error = f'[TLS RPT] DNSException: {domain} ({dex})'
            self.logger.warning(tlsrpt_error)
        except Exception as ex:
            tlsrpt_error = f'[TLS RPT] General Exception ({ex})'
            self.logger.warning(tlsrpt_error)
        return False, None, tlsrpt_error

