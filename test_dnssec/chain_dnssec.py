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

import dns
import dns.resolver

__default_ns__ = '8.8.4.4'

class ChainDnssec(object):

    def __init__(self, logger,
                 domain,
                 mx_list,
                 spf_domain=None,
                 dmarc_domain=None,
                 dkim_domain=None,
                 tlsa_list=None):

        self.logger = logger
        self.domain = domain
        self.mx_list = mx_list
        self.spf_domain = spf_domain
        self.dmarc_domain = dmarc_domain
        self.dkim_domain = dkim_domain
        self.tlsa_list = tlsa_list

    def fetch_dns_record(self, fqdn, record_type):
        '''
        Sends a DNS request for domain 'fqdn' and record 'record_type'

        :param fqdn: String, name of the domain we are requesting
        :param record_type: String, type of record we are searching (e.g., MX, TXT, ...)
        :return: dns.message.Message Object
                 String, error (if any)
        '''

        try:
            domain_name = dns.name.from_text(fqdn)
            rd_type = dns.rdatatype.from_text(record_type)
            self.logger.debug("Sending DNS request for type %s and domain %s" % (fqdn, record_type))
            resolver = dns.resolver.Resolver()
            resolver.nameservers = ([__default_ns__])
            answers = resolver.query(domain_name, rd_type, dns.rdataclass.IN, tcp=True)
            return answers.response, None
        except dns.resolver.NXDOMAIN:
            dns_error = '[DNS Resolver %s] NXDOMAIN: %s' % (record_type, fqdn)
        except dns.resolver.Timeout:
            dns_error = '[DNS Resolver %s] Timeout: %s' % (record_type, fqdn)
        except dns.resolver.YXDOMAIN :
            dns_error = '[DNS Resolver %s] YXDOMAIN: %s' % (record_type, fqdn)
        except dns.resolver.NoAnswer:
            dns_error = '[DNS Resolver %s] NoAnswer: %s' % (record_type, fqdn)
        except dns.resolver.NoNameservers :
            dns_error = '[DNS Resolver %s] NoNameservers : %s' % (record_type, fqdn)
        except dns.exception.DNSException as dex:
            dns_error = '[DNS Resolver %s] DNSException: %s (%s)' % (record_type, fqdn, str(dex))
        except Exception as ex:
            dns_error = '[DNS Resolver %s] General Exception %s (%s)' % (record_type, fqdn, str(ex))
        self.logger.warning(dns_error)
        return None, dns_error

    def get_dns_chain(self, domain, record_type):
        '''
        Given a domain and a record_type, it returns a list of all domains involved in the DNS resolution.

        :param domain: String, name of the domain we are requesting
        :param record_type: String, type of record we are searching (e.g., MX, TXT, ...)
        :return: list of tuples: ('domain_name', 'record_type')
        '''
        response, error_msg = self.fetch_dns_record(domain, record_type)
        if response is None:
            return [], error_msg
        dns_chain = []
        current_domain_name = dns.name.from_text(domain)
        found = False
        error_msg = None
        while not found and error_msg is None:
            try:
                # We look for the target record: 'record_type' (e.g. TXT or TLSA)
                rrset = response.get_rrset(response.answer,
                                           current_domain_name,
                                           dns.rdataclass.IN,
                                           dns.rdatatype.from_text(record_type))
                if rrset is not None:
                    dns_chain.append((str(current_domain_name), record_type))
                    found = True
                # If not found, we look for a CNAME record
                else:
                    rrset = response.get_rrset(response.answer,
                                               current_domain_name,
                                               dns.rdataclass.IN,
                                               dns.rdatatype.from_text('CNAME'))
                    if rrset is not None:
                        dns_chain.append((str(current_domain_name), 'CNAME'))
                        # e.g of rrset: "_dmarc.fake.dcslab.eu. 300 IN CNAME _dmarc.gmail.com."
                        cname_domain = str(rrset).strip().split()[-1]
                        self.logger.debug("get_dns_chain, "
                                          "domain %s has CNAME %s " % (str(current_domain_name),  cname_domain))
                        current_domain_name = dns.name.from_text(cname_domain)
                    else:
                        error_msg = "Broken DNS chain, domain %s does not have record %s. " % (domain, record_type)
                # Sanity check to count loops
                if len(dns_chain) > 10 and not found:
                    error_msg = "Too many CNAMEs when looking for %s %s " % (domain, record_type)

            except Exception as ex:
                error_msg = ("GENERAL Exception at chain_dnssec.get_dns_chain "
                             "for domain %s and record type %s (%s)" % (domain, record_type, str(ex)))
                self.logger.error(error_msg)

        return dns_chain, error_msg


    def execute(self):
        '''
        main process that generates a the list of values 'domain'/'record_type' that must be checked to
        evaluate the presence of DNSSEC.

        :return: list of list of values e.g.:
               [( 'MX', [('domain', 'MX')]),
               ( 'MX_A', [('domain_mx1', 'A'), ..., ('domain_mxN', 'A')]),
               ( 'SPF', [('domain', 'CNAME'), ('domain_cname', 'TXT')),
               ( 'DMARC', [('domain', 'TXT')),
               ...,
               ( '', [()])]
        '''

        error_msg = None
        full_dns_chain = []
        if self.domain is not None:
            (domain_chain, error_msg) = self.get_dns_chain(self.domain, "MX")
            if error_msg is None:
                full_dns_chain.append(("MX", domain_chain))
            else:
                self.logger.warning("ChainDnssec.MX: error fetching MX names (%s)" % str(error_msg))
        else:
            return full_dns_chain, "ChainDnssec.MX, Missing Domain Name."

        if self.mx_list:
            mx_domains = []
            for mx_domain in self.mx_list:
                (mx_chain, error_msg) = self.get_dns_chain(mx_domain, "A")
                if error_msg is None:
                    mx_domains.extend(mx_chain)
                else:
                    self.logger.warning("ChainDnssec.MX_A: error fetching MX_A (%s)" % str(error_msg))
            if len(mx_domains) > 0:
                full_dns_chain.append(('MX_A', mx_domains))
        else:
            return full_dns_chain, "ChainDnssec.execute, Missing MX list."

        if self.spf_domain is not None:
            (spf_chain, error_msg) = self.get_dns_chain(self.spf_domain, "TXT")
            if error_msg is not None:
                return full_dns_chain, error_msg
            else:
                full_dns_chain.append(("SPF", spf_chain))

        if self.dmarc_domain is not None:
            (dmarc_chain, error_msg) = self.get_dns_chain(self.dmarc_domain, "TXT")
            if error_msg is not None:
                return full_dns_chain, error_msg
            else:
                full_dns_chain.append(("DMARC", dmarc_chain))

        if self.dkim_domain is not None:
            (dkim_chain, error_msg) = self.get_dns_chain(self.dkim_domain, "TXT")
            if error_msg is not None:
                return full_dns_chain, error_msg
            else:
                full_dns_chain.append(("DKIM", dkim_chain))

        if self.tlsa_list:
            tlsa_domains = []
            for tlsa_domain in self.tlsa_list:
                (tlsa_chain, error_msg) = self.get_dns_chain(tlsa_domain, "TLSA")
                if error_msg is None:
                    tlsa_domains.extend(tlsa_chain)
                else:
                    self.logger.warning("ChainDnssec.TLSA: error fetching TLSA rcords (%s)" % str(error_msg))
            full_dns_chain.append(('TLSA', tlsa_domains))

        return full_dns_chain, error_msg
