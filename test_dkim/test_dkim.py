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

__default_ns__ = '8.8.8.8'


class DkimTest(object):

    def __init__(self, logger):
        self.logger = logger

    def test_dkim(self, domain):

        try:
            has_dkim = False
            name_servers, ns_addressess = self.get_name_servers(domain)
            if ns_addressess is None or len(ns_addressess) < 1:
                ns_addressess = [__default_ns__]
            has_dkim, dkim_error = self.check_dkim(domain, ns_addressess)
        except Exception as ex:
            dkim_error = "General error Testing DKIM for domain %s (%s)" % (domain, str(ex))
            self.logger.error(dkim_error)
        return has_dkim, dkim_error

    def get_name_servers(self, domain):
        '''
        Returns a list of authoritative Name Servers for the domain 'domain', and a list
        of 'A' records for these NS.

        :param domain: String, domain name we are testing.
        :return: List of NameServers
                 List of Ips
        '''
        resolver = dns.resolver.Resolver()
        resolver.use_edns(0, dns.flags.DO, 4096)
        resolver.nameservers = ([__default_ns__])

        ns_names = []
        ns_ips = []
        try:
            response_ns = resolver.query(domain, 'NS')
        except Exception as ex:
            self.logger.warning("DKIM Error Resolving NS %s (%s)" % (domain, str(ex)))
            return None, None
        for ns in response_ns:
            try:
                response_a = resolver.query(ns.target, 'A')
                ns_names.append(ns.target.to_text())
                for a in response_a:
                    ns_ips.append(a.address)
            except Exception as ex:
                self.logger.warning("DKIM Resolving A %s (%s)" % (ns.target.to_text(), str(ex)))
        if len(ns_names) == 0 or len(ns_ips) == 0:
            return None, None
        return ','.join(ns_names), ns_ips


    def check_dkim(self, domain, ns):
        '''
        Given a domain, query the DNS server for _domainkey.<domain>
        if the server does not support DKIM, the answer should be NXDOMAIN

        :param domain: Domain name tested
        :param ns: List of IP addressedd of for the Name Servers of 'domain'
        :return: (boolean, String[])
                  domain has DKIM record? True:False
                  answer sent from the domain Server
        '''
        try:
            self.logger.info('DKIM for domain _domainkey.%s with NS (%s)' % (domain, str(ns)))
            resolver = dns.resolver.Resolver()
            resolver.use_edns(0, dns.flags.DO, 4096)
            resolver.nameservers = ns
            resolver.query('_domainkey.' + domain, 'TXT')
            has_dkim = True
            dkim_error = 'NO Error.'
        except dns.resolver.NXDOMAIN:
            has_dkim = False
            dkim_error = 'NXDOMAIN: _domainkey.' + domain + ' [DKIM]'
            self.logger.warning(dkim_error)
        except dns.resolver.Timeout:
            has_dkim = True
            dkim_error = 'Timeout: _domainkey.' + domain + '  [DKIM]'
            self.logger.warning(dkim_error)
        except dns.resolver.NoAnswer:
            has_dkim = True
            dkim_error = 'NoAnswer: _domainkey.' + domain + ' [DKIM]'
            self.logger.warning(dkim_error)
        except dns.exception.DNSException as dex:
            has_dkim = True
            dkim_error = 'DNSException: _domainkey.' + domain + ' [DKIM] ' + str(dex)
            self.logger.warning(dkim_error)
        except Exception as ex:
            has_dkim = True
            dkim_error = 'General Exception [DKIM] (%s)' % str(ex)
            self.logger.warning(dkim_error)
        return has_dkim, dkim_error

