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
import dns.dnssec
import hashlib
import struct
import base64
from .chain_dnssec import ChainDnssec
from .cache_dnssec import CacheDnssec


__default_ns__ = '8.8.8.8'


class Dnssec(object):

    def __init__(self, logger, cache_dnssec=None):
        self.logger = logger
        self.check_txt = False
        self.check_dkim = False
        self.selector = None
        self.check_dmarc = False
        self.check_tlsa = False
        if cache_dnssec is None:
            self.cache_dnssec = CacheDnssec(logger)
        else:
            self.cache_dnssec = cache_dnssec

    def set_txt_test(self, value):
        '''
        Sets a parameter (boolean) to decide whether check the DNSEEC support in TXT records. (Default False)
        This parameter is set only if the domain supports SPF!
        :param value: boolean, indicates whether we want to test the TXT records.
        :return: -
        '''
        self.check_txt = value

    def set_dkim_test(self, selector):
        '''
        Sets the parameter 'check_dkim'. It indicates that the DNSSEC test must also check the following domain for
        DNSSEC support:   <selector>._domainkeys.<domain>
        :param selector: String representing the selector value received
        :return: -
        '''
        self.check_dkim = True
        self.selector = selector

    def set_dmarc_test(self, value):
        '''
        Sets a parameter (boolean) to decide whether check the DNSEEC support in DMARC records. (Default False)
        :param value: boolean, indicates whether we want to test the DMARC records.
        :return: -
        '''
        self.check_dmarc = value

    def set_tlsa_test(self, value):
        '''
        Sets a parameter (boolean) to decide whether check the DNSSEC support in TLSA records. (Default False)
        :param value: boolean, indicates whether we want to test the TLSA records.
        :return: -
        '''
        self.check_tlsa = value

    def get_chain(self, domains):
        '''
        Given a list of domains hierarchically ordered, it will return a list of pairs children/parent
            domains = ['1', '2', ..., 'N']
            results = [{1,2}, {2,3}, ..., {(N-1),N}]

        :param domains: list of domain names ordered by hierarchy, from children to parent.
        :return: list of pairs children-parent.
                 String, error (if any)
        '''

        try:
            if len(domains) < 2:
                return None, 'Not enough domains!'
            results = []
            index = len(domains) - 1
            while index > 0:
                result = {}
                result['children'] = domains[index-1]
                result['parent'] = domains[index]
                results.append(result)
                index -= 1
            self.logger.debug(" Chain of children-parent: %s" % str(results))
        except Exception as ex:
            chain_error = "get_chain! General Exception (%s)" % str(ex)
            self.logger.error(chain_error)
            return None, chain_error
        return results, None

    def getSOA_list(self, domain_name):
        '''
        Given a domain with multiple subdomains, it will return a list
        with all the domain-names that have a SOA record, along with the ips of their nameservers.
        The last domain name will always be '.'

        :param domain_name: String, the domain from wich we want to extract the list of SOA names.
        :return: list of soa_name where soa_name is:
                    soa_name['domain'] ->  sub-domain name
                    soa_name['ns'] -> list of ipv4 addresses of the soa_name['domain']'s NameServers
                 String, error (if any)
        '''
        domain = domain_name
        soa_names = []
        try:
            while domain != '.' and domain != '':
                (domain, ns) = self.getSOA(domain)
                parts = domain.split('.')
                if len(parts) > 1:
                    soa_name = {}
                    soa_name['domain'] = domain
                    soa_name['ns'] = ns
                    soa_names.append(soa_name)
                    parts.pop(0)
                    domain = '.'.join(parts)
            soa_name = {}
            soa_name['domain'] = '.'
            (domain, ns) = self.getSOA('.')
            soa_name['ns'] = ns
            soa_names.append(soa_name)
            return soa_names, None
        except Exception as ex:
            error_soa = "getSOA_list for domain %s (%s)" % (domain_name, str(ex))
            self.logger.error(error_soa)
            return None, error_soa

    def getNS(self, domain):
        '''
        Returns a list of authoritative Name Servers for the domain 'domain', and a list
        of 'A' records for these NS.

        :param domain: String, SOA domain name we are testing.
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
            self.logger.warning("Error Resolving NS %s (%s)" % (domain, str(ex)))
            return None, None
        for ns in response_ns:
            try:
                # self.logger.debug("Resolving A record for NS " + ns.target.to_text() + " (domain=" + domain + ")")
                response_a = resolver.query(ns.target, 'A')
                ns_names.append(ns.target.to_text())
                for a in response_a:
                    ns_ips.append(a.address)
            except Exception as ex:
                self.logger.warning("Resolving A %s (%s)" % (ns.target.to_text(), str(ex)))
        if len(ns_names) == 0 or len(ns_ips) == 0:
            return None, None
        return ','.join(ns_names), ','.join(ns_ips)

    def getCNAME(self, domain):
        '''
        Returns the CNAME that MUST resolve a TLSA record.

        :param domain: String, TLSA domain name.
        :return: Boolean, DNS query successful? True:False
                 String, cname
                 String, error (if any)
        '''
        resolver = dns.resolver.Resolver()
        resolver.use_edns(0, dns.flags.DO, 4096)
        resolver.nameservers = ([__default_ns__])
        try:
            cnames = resolver.query(domain, 'CNAME')
            if cnames is not None and len(cnames) > 0:
                return True, str(cnames[0]), None
        except Exception as ex:
            error = "Error Resolving CNAME %s (%s)" % (domain, str(ex))
            self.logger.warning(error)
            return False, None, error

    def getSOA(self, domain):
        '''
        Given a domain with multiple subdomains, it will return the first domain-name with a SOA record.
        First will try to find it in the cache. If it is not in the cache, it will send a DNS SOA request.

        :param domain: domain['domain'] -> domain name
        :return: String, the first sub-domain that is a SOA
                 String, IPv4 addresses of the SOA domain
        '''
        domain_name = domain.lower()
        try:
            results, error_msg = self.cache_dnssec.select_soa(domain_name)
            if results is not None:
                # self.logger.debug("Select SOA results found in Cache for %s" % domain_name)
                is_soa = results['ds_is_soa']
                ns_ipv4 = results['ds_ns_ipv4']
            else:
                self.logger.debug("Select SOA results NOT found in Cache for %s" % domain_name)
                (is_soa, ns_ipv4) = self.isSOA(domain_name)

            if is_soa is False:
                parts = domain.split('.')
                parts.pop(0)
                # self.logger.debug("getSOA join parts " + '.'.join(parts))
                (domain, ns_ipv4) = self.getSOA('.'.join(parts))
            return domain, ns_ipv4
        except Exception as ex:
            self.logger.error('getting SOA for domain %s (%s)' % (domain_name, str(ex)))
            return None, None

    def isSOA(self, domain):
        '''
        Checks if a domain is a Start of Authority (SOA) and updates the cache domain_soa.

        :param domain: String, domain name to test if it is SOA
        :return: Boolean, domain is SOA? True:False
                 String, ipv4 addresses
        '''
        error_msg = None
        ds_row = self.init_ds_row(domain)
        try:
            domain_name = dns.name.from_text(domain)
            rd_type = dns.rdatatype.from_text('SOA')
            resolver = dns.resolver.Resolver()
            resolver.use_edns(0, dns.flags.DO, 4096)
            response = resolver.query(domain_name, rd_type).response
            rrset = response.find_rrset(response.answer, domain_name, dns.rdataclass.IN, rd_type)
            if rrset is not None:
                ds_row['ds_is_soa'] = True
                (ds_row['ds_ns'], ds_row['ds_ns_ipv4']) = self.getNS(domain)
                self.logger.debug("[SOA Resolver] Domain %s IS SOA." % domain)
                self.cache_dnssec.insert_soa(domain, ds_row)
                return ds_row['ds_is_soa'], ds_row['ds_ns_ipv4']
            else:
                error_msg = "[SOA Resolver] Domain %s NOT SOA." % domain
        except KeyError as kex:
            error_msg = '[SOA Resolver] KeyError: %s (%s)' % (domain, str(kex))
        except dns.resolver.NXDOMAIN:
            error_msg = '[SOA Resolver] NXDOMAIN: %s' % (domain)
        except dns.resolver.Timeout:
            error_msg = '[SOA Resolver] Timeout: %s' % (domain)
        except dns.resolver.YXDOMAIN:
            error_msg = '[SOA Resolver] YXDOMAIN: %s' % (domain)
        except dns.resolver.NoAnswer:
            error_msg = '[SOA Resolver] NoAnswer: %s' % (domain)
        except dns.resolver.NoNameservers:
            error_msg = '[SOA Resolver] NoNameservers : %s' % (domain)
        except dns.exception.DNSException as dex:
            error_msg = '[SOA Resolver] DNSException: %s (%s)' % (domain, str(dex))
        except Exception as ex:
            error_msg = '[SOA Resolver] General Exception %s (%s)' % (domain, str(ex))
        self.logger.warning(error_msg)
        self.cache_dnssec.insert_soa(domain, ds_row)
        return False, None

    def validate_KSK_key(self, dskeys, rrkeys, fqdn):
        '''
        This function will check if there is a match between a Hash of a KSK in 'rrkeys'
        and the DS digest.

        :param dskeys: Set of DS keys from 'fqdn' parent
        :param rrkeys: RRKEYs from 'fqdn'
        :param fqdn: String, Full Qualified Domain Name tested
        :return: Boolean, DS digest == KSK digest? True:False
                 String, error message (if any)
        '''

        try:
            key_digest = dict()
            for dskey in dskeys:
                key_digest[dskey.digest.hex()] = dskey
            self.logger.debug("DSKEY key digest:\n{0}".format(key_digest))
            for rrkey in rrkeys:
                self.logger.info(rrkey)
                #flags = rrkey.flags_to_text_set()
                flags = rrkey.flags
                self.logger.debug("Flags of RRKEYs for %s: %s" % (str(fqdn), str(flags)))
                # 'SEP' flag is not mandatory, therefore we will test all keys.
                # if 'SEP' in flags:
                if str(fqdn)[-1] == '.':
                    owner = str(fqdn).lower()
                else:
                    owner = str(fqdn).lower() + '.'
                owner_bin = b''
                for name in owner.split('.'):
                    owner_bin += struct.pack('B', len(name)) + name.encode()
                key = base64.b64encode(rrkey.key)
                raw = struct.pack(
                    '!HBB',
                    int(rrkey.flags),
                    int(rrkey.protocol),
                    int(rrkey.algorithm))
                raw = raw + base64.b64decode(key)
                raw = owner_bin + raw
                sha1_digest = hashlib.sha1(raw).hexdigest()
                sha2_digest = hashlib.sha256(raw).hexdigest()
                sha3_digest = hashlib.sha384(raw).hexdigest()
                if sha3_digest in key_digest:
                    self.logger.info('SHA384 digest match! %s' % str(fqdn))
                    return True, None
                elif sha2_digest in key_digest:
                    return True, None
                elif sha1_digest in key_digest:
                    self.logger.warning('SHA1 digest match! %s' % str(fqdn))
                    return True, None
            error_msg = ("H(ksk) not found! %s" % str(fqdn))
            self.logger.warning(error_msg)
            return False, error_msg
        except Exception as es:
            error_msg = "Validating KSK key for %s (%s)" % (str(fqdn), str(es))
            self.logger.error(error_msg)
            return False, error_msg

    def check_DS_records(self, children_domain, parent_ns):
        '''
        It will compare the answers from all NameServers, and returns the ones that are
        common to all of the NSs. If there is no common answer, it will return False.

        :param children_domain: String, domain assessed
        :param parent_ns: List of String, Ip addresses of the Name Servers of the parent domain od 'children_domain'
        :return: Return the set of DS records for the given domain, using name_server as DNS
                 server (domain=children, name_server=parent_ns)
                 String, Error (if any)
        '''

        resolver = dns.resolver.Resolver()
        resolver.use_edns(0, dns.flags.DO, 4096)
        responses = None
        valid_responses = 0
        timeouts = 0
        try:
            sets = []
            dskeys = []
            for ns in parent_ns:
                try:
                    ns_set = set()
                    ns_dskeys = []
                    ns_dskey = {}
                    resolver.nameservers = ([ns])

                    responses = resolver.query(children_domain, 'DS')
                    for response in responses:
                        key = hashlib.sha256(response.to_text().encode("utf-8")).hexdigest()
                        ns_set.add(key)
                        ns_dskey[key] = response
                        ns_dskeys.append(ns_dskey)
                        valid_responses += 1 #increment valid responses
                    sets.append(ns_set)
                    dskeys.append(ns_dskeys)
                except dns.resolver.NXDOMAIN:
                    error_msg = "getDSrecord NXDOMAIN: %s" % children_domain
                    self.logger.warning(error_msg)
                    return None, error_msg
                except dns.resolver.Timeout:
                    error_msg = "getDSrecord Timeout: %s" % children_domain
                    self.logger.warning(error_msg)
                    timeouts += 1 # increment timeouts
                except dns.resolver.NoAnswer:
                    error_msg = "getDSrecord NoAnswer: %s" % children_domain
                    self.logger.warning(error_msg)
                    return None, error_msg
                except dns.exception.DNSException as dex:
                    error_msg = "getDSrecord DNSException: %s (%s)" % (children_domain, str(dex))
                    self.logger.warning(error_msg)
                    return None, error_msg
                except Exception as ex:
                    error_msg = "getDSrecord Exception: %s (%s)" % (children_domain, str(ex))
                    self.logger.warning(error_msg)
                    return None, error_msg
            ds_common = set.intersection(*sets)
            if ds_common is None or len(ds_common) == 0:
                error_msg = "Inconsistent DS records %s" % children_domain
                self.logger.warning(error_msg)
                return None, error_msg
            # What happens if we have: R1 = [a,b]; R2 = [a,b,c]
            # should the 'c' result raise a Warning or Erorr?
            # should we have only One common result?

            # If no valid_responses or too many timeouts show error
            if valid_responses == 0:
                error_msg = "Not enough valid responses"
                self.logger.warning(error_msg) 
                return None, error_msg
            if timeouts > valid_responses:
                error_msg = "Too many timeouts: %s (valid responses: %s)" % (timeouts, valid_responses)
                self.logger.warning(error_msg) 
                return None, error_msg

            return responses, None
        except Exception as ex:
            error_msg = "getDSrecord: %s (%s)" % (children_domain, str(ex))
            self.logger.error()
            return None, error_msg

    def getRRSIG(self, domain, name_server, record, use_tcp=True, attempt=1):
        '''
        Return the set of RRSIG records for the given domain, as obtained from
        the given server: 'name_server'

        :param domain: String, domain name assessed
        :param name_server:  String, IPv4 address of the Name Server used in the DNS query
        :param record: String, DNS record type requested e.g. (TXT, A, ...)
        :param use_tcp: Boolean, indicates if the DNS request is TCP or UDP.
        :param attempt: integer, to ensure we repeat the DNS request only once, when the result is Timeout.
        :return: Set of RRSIG values
                 Set of RRSET values
                 String, error (if any)
        '''

        resolver = dns.resolver.Resolver()
        resolver.use_edns(0, dns.flags.DO, 4096)
        resolver.nameservers = ([name_server])

        domain_name = dns.name.from_text(domain)
        rd_type = dns.rdatatype.from_text(record)
        rd_class = dns.rdataclass.IN

        error_msg, rrsig, rrset = (None, None, None)
        try:
            response = resolver.query(domain_name, rd_type, rd_class, tcp=use_tcp).response
            rrsig = response.find_rrset(response.answer, domain_name, rd_class, dns.rdatatype.RRSIG, rd_type)
            rrset = response.find_rrset(response.answer, domain_name, rd_class, rd_type)
        except dns.resolver.NXDOMAIN:
            error_msg = ("getRRSIG %s, %s NXDOMAIN " % (record, domain))
            self.logger.warning(error_msg)
        except dns.resolver.Timeout:
            error_msg = ("getRRSIG %s, %s Timeout " % (record, domain))
            self.logger.warning(error_msg)
            if attempt == 1:
                self.logger.warning("TCP Query Failed, attempting UDP for %s %s" % (record, domain))
                rrsig, rrset, error_msg = self.getRRSIG(domain, name_server, record, use_tcp=False, attempt=2)
        except dns.resolver.NoAnswer:
            error_msg = ("getRRSIG %s, %s No Answer Returned " % (record, domain))
            self.logger.warning(error_msg)
        except dns.exception.DNSException as dex:
            error_msg = ("getRRSIG %s, %s  DNSException (%s)" % (record, domain, str(dex)))
            self.logger.warning(error_msg)
            if attempt == 1:
                self.logger.warning("TCP Query Failed, attempting UDP for %s %s" % (record, domain))
                rrsig, rrset, error_msg = self.getRRSIG(domain, name_server, record, use_tcp=False, attempt=2)
        except KeyError as kex:
            error_msg = ("getRRSIG %s, %s KeyError (%s)" % (record, domain, str(kex)))
            self.logger.warning(error_msg)
        except Exception as ex:
            error_msg = ("getRRSIG %s, %s GeneralException (%s)" % (record, domain, str(ex)))
            self.logger.warning(error_msg)
        return rrsig, rrset, error_msg

    def check_RRSIG_dnskey(self, domain, children_ns, record):
        '''
        Checks if 'domain' has a valid DNSKEY.

        It will query each name_server in the children_ns list and compare the
        responses (signatures, records). If there is at least one common answer, it will return
        the result from the last query.

        :param domain: String, domain name assessed
        :param children_ns: List of IPv4 addressed of the Name Servers of 'domain'
        :param record: String, record type requested (DNSKEY)
        :return: Set of RRSIG values
                 Set of RRSET values
                 String, error (if any)
        '''
        unsupported_algo = ['12', '15', '16']

        dns_name = dns.name.from_text(domain)
        # a list of ns_set
        sets = []
        for ns in children_ns:
            # a set of hash(value)
            ns_set = set()
            # a list of ns_rrset
            ns_rrsets = []
            # a pair of (key,value) where key = hash(value)
            ns_rrset = {}
            rrsig, rrset, error_msg = self.getRRSIG(domain, ns, record)
            sigarray = str(rrset).split()
            if rrsig is None or rrset is None:
                return None, None, error_msg
            try:
                dns.dnssec.validate(rrset, rrsig, {dns_name: rrset})
            except Exception as ex:
                if sigarray[6] in unsupported_algo:
                    unsupported_error = "MECSA does not support this algorithm yet, we cannot validate DNSSEC."
                    self.logger.warning("Unsupported algorithm %s (%s)" % (domain, str(ex)))
                    return None, None, unsupported_error
                error_msg = ("Validating DNSKEYS %s (%s)" % (domain, str(ex)))                
                self.logger.warning(error_msg)
                return None, None, error_msg
            for value in rrset:
                key = hashlib.sha256(value.to_text().encode("utf-8")).hexdigest()
                ns_set.add(key)
                ns_rrset[key] = value
                ns_rrsets.append(ns_rrset)
            sets.append(ns_set)
        # if we arrive to this point, it means that all rrsig and rrset are
        # correctly signed, now lets checkl if we have, at least,
        # one common value
        keys_common = set.intersection(*sets)
        if keys_common is None or len(keys_common) == 0:
            error_msg = "No Common DNSKEYS! for Domain %s " % domain
            self.logger.warning(error_msg)
            return None, None, error_msg
        # same, same than checking DS, what happens when we have extra results??
        return rrsig, rrset, None

    def check_RRSIG_record(self, domain, children_ns, record, dnskeys):
        '''
        Tests if the DNS record 'record' of domain 'domain' is protected with DNSSEC.

        It will query each name_server in the children_ns list and compare the
        responses (signatures, records). If they are all the same, it will
        return the result from the last query (at least there must be one common
        answer to al NSs).

        :param domain: String, domain name assessed
        :param children_ns: List of IPv4 addressed of the Name Servers of 'domain'
        :param record: String, record type requested
        :param dnskeys: Set of DNSKeys fo the domain 'domain'
        :return: Boolean, domain record is DNSSEC protected? True:False
                 String, error (if any)
        '''

        try:
            # a list of ns_set
            sets = []
            for ns in children_ns:
                # a set of hash(value)
                ns_set = set()
                # a list of ns_rrset
                ns_rrsets = []
                # a pair of (key,value) where key = hash(value)
                ns_rrset = {}
                (rrsig, rrset, error_msg) = self.getRRSIG(domain, ns, record)
                if (rrsig is None) or (rrset is None):
                    return False, error_msg
                try:
                    dns.dnssec.validate(rrset, rrsig, dnskeys)
                except Exception as ex:
                    error_msg = ("Validating DNSSEC records %s for domain %s (%s)" % (record, str(domain), str(ex)))
                    self.logger.warning(error_msg)
                    return False, error_msg
                for value in rrset:
                    key = hashlib.sha256(value.to_text().encode("utf-8")).hexdigest()
                    ns_set.add(key)
                    ns_rrset[key] = value
                    ns_rrsets.append(ns_rrset)
                sets.append(ns_set)
            # if we arrive to this point, it means that all rrsig and rrset are
            # correctly signed, now lets check if we have, at least,
            # one common value
            keys_common = set.intersection(*sets)
            if keys_common is None or len(keys_common) == 0:
                error_msg = ("ERROR No Common RESULT  for record: %s" % record)
                self.logger.warning(error_msg)
                return False, error_msg
            # same, same than checking DS, what happens when we have
            # extra results??
            return True, None
        except Exception as ex:
            error_msg = ("check_RRSIG_record General Exception, %s %s (%s)" % (record, str(domain), str(ex)))
            self.logger.error(error_msg)
            return False, error_msg

    def test_chain(self, chain):
        '''
        Checks if the list of SOAs chain support DNSSEC in ALL sub-domains.
        1. searches in the DB if the sub-domain has been tested.
          1.a. if the sub-domain has been tested and is false, return False.
          1.b. if the sub-domain has not been tested, it tests the sub-domain and updated the DB.

        :param chain: List of children-parent soa sub_domains, where each subdomain is:
                    sub_domain['domain'] -> sub_domain name
                    sub_domain['ns'] -> list of the ip addresses of the sub_domain NameServers
        :return: (All children sub_domains support DNSSEC? True:False , Error_Message)
        '''
        try:
            for subdomain in chain:
                children_subdomain = subdomain['children']['domain']
                children_ns = subdomain['children']['ns'].split(',')
                parent_ns = subdomain['parent']['ns'].split(',')

                try:
                    results, error_msg = self.cache_dnssec.select_soa_dnssec(children_subdomain)
                    if results is not None:
                        if results['ds_is_dnssec'] is False:
                            error_msg = ("test_chain: chain broken, %s is not dnssec " % children_subdomain)
                            return False, error_msg
                    else:
                        (has_dnssec, dnssec_error) = self.check_subdomain(children_subdomain, parent_ns, children_ns)
                        self.cache_dnssec.update_soa(dnssec_error, has_dnssec, children_subdomain)
                        if has_dnssec is False:
                            return False, dnssec_error
                except Exception as ex:
                    error_msg = ("test_chain: Chain Exception, %s is not dnssec  (%s)" % (children_subdomain, str(ex)))
                    self.logger.warning(error_msg)
                    return False, error_msg
            return True, None
        except Exception as ex:
            error_msg = "test_chain: General Exception, %s (%s)" % (str(chain), str(ex))
            self.logger.error(error_msg)
            return False, error_msg

    def check_subdomain(self, domain, parent_ns, children_ns):
        '''
        Tests if a domain has dnssec enabled:
            1. Check if it has DS record in the parent NS
            2. Check it if has a DNSKEY record
            3. Check id the KSK matches the DS record.

        :param domain: domain name to be tested (domain = children_domain).
        :param parent_ns: list of NameServer ip addresses of the parent domain
        :param children_ns: list of NameServer ip addresses of the domain
        :return: (domain supports dnssec? True:False, error_msg)
        '''
        try:
            # print "check DS records"
            (ds_records, error_msg) = self.check_DS_records(domain, parent_ns)
            self.logger.debug("%s has DS records? %s" % (domain, str(ds_records is not None)))
            if ds_records is None:
                return False, error_msg
            # print "check DNSKEYs"
            (rrsig_dns, rrset_dns, error_msg) = self.check_RRSIG_dnskey(domain, children_ns, 'DNSKEY')
            self.logger.debug("%s has DNSKEYS? %s" % (domain, str(rrsig_dns is not None)))
            if rrsig_dns is None:
                return False, error_msg
            # print "check KSK"
            (ksk, error_msg) = self.validate_KSK_key(ds_records, rrset_dns, domain)
            self.logger.debug("%s has valid KSK? %s" % (domain, str(ksk)))
            if ksk is False:
                return False, error_msg
        except Exception as ex:
            error_msg = "EXCEPTION check_domain: %s (%s)" % (domain, str(ex))
            self.logger.error(error_msg)
            return False, error_msg
        return True, None

    def test_domain_name(self, domain_name):
        '''
        Checks if the domain_name supports dnssec:

        1. obtain the list of SOA sub-domains from 'domain'
           domain_soa['doamin'] -> sub-domain soa
           domain_soa['ns']     -> list of ipv4 addressed of the sub-domain's NameServers
        2. obtain the chain children-parent from the list of sub-domains SOA
        3. test the validity of the KEY chain, i.e. all children in the chain have a DS record
           in the parent NameServer, and the KSK of the children matches the DS record found.

        :param domain_name: String, domain to be tested (must end with '.', e.g. example.com.)
        :return: dnssec_chain (domain_name supports dnssec? True:False)
                 trust_chain (list from step 2)
                 String, error message (if any)
                 Set of DNSkeys
        '''
        try:
            # 1.
            self.logger.debug("-----> DNSSEC Testing %s" % domain_name)
            domain_soas, error_soa = self.getSOA_list(domain_name)
            if domain_soas is None:
                return False, None, error_soa, None

            # 2.
            trust_chain, trust_chain_error = self.get_chain(domain_soas)
            if trust_chain is None:
                return False, None, trust_chain_error, None
            self.logger.debug('Trust Chain: %s ' % str(trust_chain))

            # 3.
            dnssec_chain, error_msg = self.test_chain(trust_chain)

            dnskeys = None
            if dnssec_chain:
                # 4.
                chain = trust_chain[-1] # the last component of the Trust-Chain contains the first SOA subdomain.
                test_domain = chain['children']['domain']
                test_ns = chain['children']['ns'].split(',')

                # fetch the DNSKEYS to test the dnssec support of the different records.
                (rrsig_dns, rrset_dns, error_msg) = self.check_RRSIG_dnskey(test_domain, test_ns, 'DNSKEY')
                dns_name = dns.name.from_text(test_domain)
                dnskeys = {dns_name: rrset_dns}

            return dnssec_chain, trust_chain, error_msg, dnskeys
        except Exception as ex:
            error_msg = "test_domain_name %s (%s)" % (domain_name, str(ex))
            self.logger.error(error_msg)
            return False, None, error_msg, None

    # DOMAIN_DNSSEC
    def init_dd_row(self, domain_name):
        '''
        Fucntion that initializes the dictionary used in the DNSSEC cache and DNSSEC assessment.

        :param domain_name: String, domain name assessed
        :return: Dictionary,

        dd_domain -------- String, domain name assessed
        dd_dnssec -------- Boolean, Overall assessement: email domain is DNSSEC protected? True:False
        dd_dnssec_a ------ Boolean, domain supports DNSSEC? True:False
        dd_dnssec_mx ----- Boolean, domain MX records are DNSSEC protected? True:False
        dd_dnssec_mx_a --- Boolean, domain_mx are DNSSEC protected? True:False
        dd_dnssec_spf ---- Boolean, domain TXT records are DNSSEC protected? True:False
        dd_dnssec_dmarc -- Boolean, _dmarc.domain is DNSSEC protected? True:False
        dd_dnssec_dkim --- Boolean, <selector>._domainkeys.domain is DNSSEC protected? True:False
        dd_dnssec_tlsa --- Boolean, _25._tcp.domain_mx are DNSSEC protected? True:False
        dd_error --------- String, error (if any)

        '''
        dd_row = {}
        dd_row['dd_domain'] = domain_name
        dd_row['dd_dnssec'] = False
        dd_row['dd_dnssec_a'] = False
        dd_row['dd_dnssec_mx'] = False
        dd_row['dd_dnssec_mx_a'] = False
        dd_row['dd_dnssec_spf'] = False
        dd_row['dd_dnssec_dmarc'] = False
        dd_row['dd_dnssec_dkim'] = False
        dd_row['dd_dnssec_tlsa'] = False
        dd_row['dd_error'] = None
        return dd_row

    def init_key_row(self):
        key_row = {}
        key_row['MX'] = 'dd_dnssec_mx'
        key_row['MX_A'] = 'dd_dnssec_mx_a'
        key_row['SPF'] = 'dd_dnssec_spf'
        key_row['DMARC'] = 'dd_dnssec_dmarc'
        key_row['DKIM'] = 'dd_dnssec_dkim'
        key_row['TLSA'] = 'dd_dnssec_tlsa'
        return key_row

    # DOMAIN_SOA
    def init_ds_row(self, domain_name):
        '''
        Function that initializes the dictionary used in the SOA cache

        :param domain_name: String, domain name assessed
        :return: Dictionary,

        ds_domain ----- String, domain name assessed
        ds_is_soa ----- Boolean, ds_domain is SOA? True:False
        ds_ns --------- List of ds_domain Name Servers
        ds_ns_ipv4 ---- List of IPv4 addresses of ds_ns
        ds_error ------ String, error (if any)
        ds_is_dnssec -- Boolean, ds_domain is DNSSEC protected? True:False
        ds_tested ----- Boolean, ds_domain has been tested for DNSSEC support? True:False
        ds_insert ----- String,

        '''
        ds_row = {}
        ds_row['ds_domain'] = domain_name
        ds_row['ds_is_soa'] = False
        ds_row['ds_ns'] = None
        ds_row['ds_ns_ipv4'] = None
        ds_row['ds_error'] = None
        ds_row['ds_is_dnssec'] = False
        ds_row['ds_tested'] = False
        # ds_row['ds_insert'] = None
        return ds_row

    def execute_test(self, domain_test, mx_test, tlsa_test):
        '''
        Test if an email domain supports DNSSEC. Complete test:
        1. test if the domain_test supports DNSSEC.
        2. test if the MX records (mx_test) of the domain_name support DNSSEC.
            for each MX:
            2.1 test if the MX hostname supports DNSSEC
            2.2 test if the MX records have the A records secured with DNSSEC
        3. test if the TXT records of domain_test support DNSSEC (optional if SPF)
        3. test if the TXT records of _dmarc.domain_test support DNSSEC (optional if DMARC)
        4. test if the TLSA records of domain_test support DNSSSEC (optional)

        :param domain_test: domain name to test
        :param mx_test: list of MX hostnames of the domain to test (ir_smtp_success must be true).
        :param tlsa_test: list of MX hostnames with DANE support to test.
        :return: Dictionary, 'dd_row' value
        '''
        try:
            if domain_test[-1] != '.':
                domain_name = domain_test + '.'
            else:
                domain_name = domain_test

            dd_row = self.init_dd_row(domain_name)
            key_row = self.init_key_row()

            #
            # 0. if we already have the value in the Cache, we return it.
            (domain_name_cached, dnssec_cached, error_msg) = self.cache_dnssec.select_from_dnssec(domain_name)
            if domain_name_cached:
                return dnssec_cached

            #
            # 1. To execute the DNSSEC test, first, we 'calculate' the list of tests to execute.
            # SPF test?
            if self.check_txt:
                domain_spf = domain_name
            else:
                domain_spf = None

            # DMARC test?
            if self.check_dmarc:
                domain_dmarc = "_dmarc.%s" % domain_name
            else:
                domain_dmarc = None

            # DKIM test?
            if self.check_dkim:
                domain_dkim = "%s._domainkey.%s" % (self.selector, domain_name)
            else:
                domain_dkim = None

            # TLSA test?
            if self.check_tlsa:
                tlsa_list = []
                for mx in tlsa_test:
                    tlsa_list.append("_25._tcp.%s" % mx)
            else:
                tlsa_list = None

            chain_dnssec = ChainDnssec(self.logger,
                                       domain_name,
                                       mx_test,
                                       domain_spf,
                                       domain_dmarc,
                                       domain_dkim,
                                       tlsa_list)

            chain_test, error_msg = chain_dnssec.execute()

            if chain_test is None or len(chain_test) < 1:
                self.logger.error("UNEXPECTED ERROR preparing DNSSEC tests for %s (%s)" % (domain_test, str(error_msg)))
                dd_row['dd_error'] = error_msg
                return dd_row

            local_cache = dict()
            for test, test_list in chain_test:
                for test_domain, test_record in test_list:
                    current_domain = str(dns.name.from_text(test_domain))
                    # check if test_domain has DNSSEC enabled
                    self.logger.info(
                        "DNSSEC-TEST [%s]: check if domain %s is DNSSEC" % (test, test_domain))
                    if test_domain in local_cache:
                        self.logger.info("DNSSEC-TEST [%s]: domain %s found in cache." % (test, test_domain))
                        cache = local_cache[test_domain]
                        dnssec, test_ns, dnskeys, error_msg = (cache['dnssec'], cache['ns'], cache['dnskeys'], cache['error'])
                    else:
                        (dnssec, trust_chain, error_msg, dnskeys) = self.test_domain_name(current_domain)
                        test_ns = trust_chain[-1]['children']['ns'].split(',')
                        local_cache[test_domain] = {'dnssec': dnssec, 'ns': test_ns, 'dnskeys': dnskeys, 'error': error_msg}
                    if dnssec is False:
                        dd_row['dd_error'] = error_msg
                        self.cache_dnssec.insert_to_dnssec(dd_row)
                        return dd_row

                    # check if test_record is protected by DNSSEC
                    self.logger.info(
                        "DNSSEC-TEST [%s]: check record %s for domain %s" % (test, test_record, test_domain))
                    (dnssec_mx, error_msg) = self.check_RRSIG_record(current_domain,
                                                                     test_ns,
                                                                     test_record,
                                                                     dnskeys)
                    if dnssec_mx is False:
                        dd_row['dd_error'] = error_msg
                        self.cache_dnssec.insert_to_dnssec(dd_row)
                        return dd_row
                dd_row[key_row[test]] = True

            # If we arrive here, the domain supports DNSSEC (strict check for complete email support)
            dd_row['dd_dnssec'] = True
            self.cache_dnssec.insert_to_dnssec(dd_row)
            return dd_row
        except Exception as ex:
            error_msg = "GENERAL DNSSEC Exception: execute_test domain: %s (%s)" % (domain_test, str(ex))
            self.logger.error(error_msg)
            dd_row['dd_error'] = error_msg
            self.cache_dnssec.insert_to_dnssec(dd_row)
            return dd_row
