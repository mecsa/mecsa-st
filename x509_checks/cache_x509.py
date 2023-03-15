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


import OpenSSL
import urllib3


class CacheX509(object):

    def __init__(self, logger):
        self.logger = logger
        self.rcls = {}

    def select_revocation_list(self, url):
        '''
        Returns the Revocation List RCL, either from the local cache or fetching it online

        :param url: String, URL pointing to the revocation list
        :return: the revocation list requested.
        '''
        try:
            if url in self.rcls:
                self.logger.debug("CRL obtained from CACHE. %s" % url)
                return self.rcls[url]
            else:
                crl = self.fetch_revocation_list(url)
                self.logger.debug("CRL obtained ONLINE. %s" % url)
                self.rcls[url] = crl
                return crl
        except Exception as ex:
            self.logger.error("Getting CRL from Cache Failed. %s (%s) " % (url, str(ex)))
            return None

    def fetch_revocation_list(self, url):
        '''
        Fetches the revocation list from the URL 'url'

        :param url: String, URL pointing to the revocation list
        :return: the revocation list requested.
        '''
        conn = None
        try:
            sslc = OpenSSL.crypto
            conn = urllib3.PoolManager()
            crl_bin = conn.request('GET', url)
            crl = sslc.load_crl(sslc.FILETYPE_ASN1, crl_bin.data)
            crl_pem = sslc.dump_crl(sslc.FILETYPE_PEM, crl)
            return crl_pem
        except Exception as ex:
            self.logger.error("Fetch CRL from ULR %s failed (%s). " % (url, str(ex)))
        finally:
            if conn is not None:
                conn.clear()
        return None