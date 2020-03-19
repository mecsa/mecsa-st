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
import spf


class Spf(object):

    def __init__(self, logger):
        self.logger = logger

    def init_spf_parameters(self):
        '''
        Initializes the dictionary used in the SPF assessment.

        :return: Dictionary,

        has_spf -------------- Boolean, has SPF record? True:False
        spf_record ----------- String, SPF record
        spf_syntax_check ----- Boolean, SPF record passed syntax check? True:False
        spf_syntax_response -- String, Response to the syntax check test
        spf_error ------------ String, error (if any)

        '''
        spf_row = {}
        spf_row['has_spf'] = False
        spf_row['spf_record'] = None
        spf_row['spf_syntax_check'] = False
        spf_row['spf_syntax_response'] = None
        spf_row['spf_error'] = None
        return spf_row

    def check_syntax_spf(self, spf_text, domain):
        '''
        Given an SPF record, it will check its syntax.

        :param spf_text: String, the SPF record to test
        :param domain: String, domain name tested
        :return:  Boolean, SPF syntax OK? True:False
                  String, code returned by the check() function (250, 500,..)
                  String, if failed, description of the syntax error.
        '''
        try:
            check_result, check_code, check_description = (None, None, None)
            q = spf.query(s='postmaster@%s' % domain, h=domain, i='127.0.0.1')
            check_result, check_code, check_description = q.check(spf=spf_text)
            self.logger.debug("SPF-SYNTAX-CHECK: %s %s %s" % (str(check_result), str(check_code), str(check_description)))
            if check_result in ["none", "permerror", "temperror"]:
                return False, check_code, check_description
            else:
                return True, check_code, check_description
        except Exception as error:
            self.logger.error("SPF-Text Syntax-Error " + str(spf_text) + ". " + str(error))
            return False, str(check_code), "SPF-Text Syntax-Error " + str(error)

    def test_spf(self, domain):
        '''
        Given a domain, it will fetch its SPF record and check its syntax.

        :param domain: Domain name tested.
        :return: Boolean, domain has SPF records? True:False
                 String, if True, it will return the SPF record. If False, it will return the corresponding error.
        '''
        row = self.init_spf_parameters()
        try:
            row['has_spf'], row['spf_record'], row['spf_error'] = self.fecth_spf(domain)
            if row['has_spf']:
                row['spf_syntax_check'], code, description = self.check_syntax_spf(row['spf_record'], domain)
                if row['spf_syntax_check']:
                    row['spf_syntax_response'] = "%s : %s" % (str(code), str(description))
                else:
                    row['spf_error'] = "%s : %s" % (str(code), str(description))
        except Exception as ex:
            row['spf_error'] = "SPF-Test Generic Error %s (%s)" % (str(domain), str(ex))
            self.logger.error(row['spf_error'])
        return row

    def fecth_spf(self, domain):
        '''
        Given a domain, it will return the SPF record, if it has one.

        :param domain: Domain name tested
        :return: Boolean, domain has SPF record? True:False
                 String[], List of TXT records for domain
                 Errors in the query
        '''
        try:
            records = 0
            spf_error = None
            has_spf = False
            spf_record = None
            self.logger.debug('sending DNS TXT request for domain ' + domain)
            answers = dns.resolver.query(domain, 'TXT')
            for answer in answers:
                record = ""
                for element in answer.strings:
                    record = record + str(element, "utf-8")
                if record.lower().startswith("v=spf1"):
                    if records < 1:
                        spf_record = record
                        has_spf = True
                        records += 1
                    else:
                        spf_record += ' ' + record
                        records += 1
                        has_spf = False
                        spf_error = 'Error: %d SPF records found' % records
            if records == 0:
                spf_error = "Error: No valid SPF record found."
            return has_spf, spf_record, spf_error
        except dns.resolver.NXDOMAIN:
            spf_error = '[SPF] NXDOMAIN: %s' % domain
            self.logger.warning(spf_error)
        except dns.resolver.Timeout:
            spf_error = '[SPF] Timeout: %s' % domain
            self.logger.warning(spf_error)
        except dns.resolver.NoAnswer:
            spf_error = '[SPF] NoAnswer: %s' % domain
            self.logger.warning(spf_error)
        except dns.exception.DNSException as dex:
            spf_error = '[SPF] DNSException: %s (%s)' % (domain, str(dex))
            self.logger.warning(spf_error)
        except Exception as ex:
            spf_error = '[SPF] General Exception (%s)' % str(ex)
            self.logger.warning(spf_error)
        return False, None, spf_error

    def sent_with_spf(self, ipv4, sender, hostname):
        '''
        Given a sender email address, the IP address of an Outbound server, and its hostname, It will check if it
        complies with the SPF policy (if any)

        :param ipv4: IP address of the Outbound server delivering the email
        :param sender: email address of the sender
        :param hostname: hostname of the Outbound server.
        :return: Boolean, SPF compliant? YES:NO
                 String, code returned bt the validation function
                 String, text returned by the validation function
        '''
        try:
            spfsupport, spfcode, spfdesc = spf.check(i=ipv4, s=sender, h=hostname)
            self.logger.debug('SPDF: ' + str(spfsupport) + ', ' + str(spfcode) + ', ' + str(spfdesc))
            if (spfsupport == 'pass' or spfsupport == 'softfail' or spfsupport == 'neutral') and 250 == spfcode:
                return True, spfcode, (spfsupport + ' : ' + spfdesc)
        except Exception as ex:
            self.logger.error("Error validating compliance with SPF! " + str(ex))
        return False, spfcode, spfdesc