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


class CacheDnssec(object):

    def __init__(self, logger):
        self.logger = logger
        self.dnssec = {}
        self.soa = {}

    # DOMAIN_DNSSEC
    def select_from_dnssec(self, domain_name):
        '''
        Checks if we already have the domain 'domain_name' in the cache.

        :param domain_name: String, domain name tested
        :return: Boolean, domain_name is in DB?True:False
                 Dictionary, 'dd_row' if found in the database, otherwise None
                 String, error message (if any)
        '''
        try:
            if domain_name in self.dnssec:
                row = self.dnssec[domain_name]
                return True, row, row['dd_error']
            else:
                return False, None, None
        except Exception as ex:
            error = "Select domain_dnssec %s (%s)" % (domain_name, str(ex))
            self.logger.error(error)
            return False, None, error

    def insert_to_dnssec(self, dd_row):
        '''
        Inserts a new row in the cache domain_dnssec.

        :param dd_row: The list of values to Insert
            dd_row['dd_domain']      String , domain tested
            dd_row['dd_dnssec']      boolean, overall value of dnssec_support (all others must be true)
            dd_row['dd_dnssec_a']    boolean, indicates the A records of dd_domain are dnssec secure
            dd_row['dd_dnssec_mx']   boolean, indicates the MX records of dd_domain are dnssec secure
            dd_row['dd_dnssec_mx_a'] boolean, indicates the A records of all MX FQDNs are dnssec secure
            dd_row['dd_dnssec_txt']  boolean, indicates the TXT records of dd_domain are dnssec secure
            dd_row['dd_dnssec_tlsa'] boolean, indicates the TLSA records of dd_domain are dnssec secure
            dd_row['dd_error']
        :return: (execution correct?True:False, error_message)
        '''
        try:
            if dd_row['dd_domain'] not in self.dnssec:
                domain = dd_row['dd_domain']
                self.dnssec[domain] = dd_row
            return True, None
        except Exception as ex:
            error_msg = "Insert domain_dnssec %s (%s)" % (dd_row['dd_domain'], str(ex))
            self.logger.error(error_msg)
            return False, error_msg

    # DOMAIN_SOA
    def select_soa(self, ds_domain):
        '''
        Checks if we already have the domain_name in the cache.

        :param domain_name:
        :return: dictionary, 'ds_row' if 'ds_domain' is already in cache, None otherwise
                 String, error (if any)
        '''
        try:
            if ds_domain in self.soa:
                row = self.soa[ds_domain]
                return row, None
            else:
                return None, None
        except Exception as ex:
            error_msg = "Select soa from cache %s (%s)" % (ds_domain, str(ex))
            self.logger.error(error_msg)
            return None, error_msg

    def select_soa_dnssec(self, ds_domain):
        '''
        Checks if we already have 'ds_domain' in the cache.

        :param ds_domain: String, domain we are looking for
        :return: dictionary, 'ds_row' if 'ds_domain' is already in cache, None otherwise
                 String, error (if any)
        '''
        try:
            if ds_domain in self.soa:
                row = self.soa[ds_domain]
                if row['ds_tested']:
                    return row, None
            return None, None
        except Exception as ex:
            error_msg = "Select dnssec domain from cache %s (%s)" % (ds_domain, str(ex))
            self.logger.error(error_msg)
            return None, error_msg

    def update_soa(self, ds_error, ds_is_dnssec, ds_domain):
        '''
        Updates the SOA cache

        :param ds_error:     String, error (if any)
        :param ds_is_dnssec: Boolean, indicates if domain supports DNSSEC
        :param ds_domain:    String, domain we are updating
        :return: Boolean, updated? True:False
                 String, error (if any) during the update
        '''
        try:
            if ds_domain in self.soa:
                ds_row = self.soa[ds_domain]
                ds_row['ds_error'] = ds_error
                ds_row['ds_is_dnssec'] = ds_is_dnssec
                ds_row['ds_tested'] = True
                self.soa[ds_domain] = ds_row
            return True, None
        except Exception as ex:
            error_msg = "Update soa in cache %s (%)" % (ds_domain, str(ex))
            self.logger.error(error_msg)
            return False, error_msg

    def insert_soa(self, ds_domain, ds_row):
        '''
        Insert a SOA domain name into the cache

        :param ds_domain: String, domain name that is SOA
        :param ds_row: dictionary,
            ds_row['dd_domain'],   domain name
            ds_row['ds_is_soa'],   indicates if domain name is SOA
            ds_row['ds_ns'],       list of NS of domain
            ds_row['ds_ns_ipv4'],  list of IPv4 addresses of NS
            ds_row['ds_error'],    if an error occurred while checking if domain name is SOA, indicates the error
            ds_row['ds_is_dnssec'], indicates if domain supports DNSSEC
            ds_row['ds_tested'], indicates it has been tested for DNSSEC support (otherwise ds_is_dnssec is Default)
            ds_row['ds_insert'],
        :return: boolean, True/False? the process ended correctly
                 string, in case of error, the error message
        '''
        try:
            if ds_domain not in self.soa:
                self.soa[ds_domain] = ds_row
            return True, None
        except Exception as ex:
            error_msg = "Insert soa in cache %s (%s)" % (ds_domain, str(ex))
            self.logger.error(error_msg)
            return False, error_msg
