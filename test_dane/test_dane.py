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
import OpenSSL
import hashlib


class DaneTLSA:
    def __init__(self, logger, root_cas):
        self.logger = logger
        self.root_cas = root_cas
        self.dane_txt = None

    def fetch_tlsa(self, mx):
        '''
        There are two possible configurations:
            1.- The MX has a TLSA record (_25._tcp.<domain>)
            2.- The MX url _25._tcp.<domain> has a CNAME record, and this CNAME record  has a TLSA record.

                Example extracted form RFC 6698
               ; TLSA record for original domain has CNAME to target domain
               ;
               sub5.example.com.            IN CNAME sub6.example.com.
               _443._tcp.sub5.example.com.  IN CNAME _443._tcp.sub6.example.com.
               sub6.example.com.            IN A 192.0.2.1
               sub6.example.com.            IN AAAA 2001:db8::1
               _443._tcp.sub6.example.com.  IN TLSA 1 1 1 536a570ac49d9ba4...

        :param mx: hostname of the MX
        :return: True/False, and a list of either TLSA records or ERRORs
        '''
        try:
            has_tlsa = False
            dane_tlsa = []
            has_tlsa, dane_tlsa = self.test_tlsa(mx)
        except Exception as ex:
            dane_tlsa.append('Exception fetching TLSA for mx %s (%s)' % (mx, str(ex)))
            self.logger.warning(str(dane_tlsa))
        return has_tlsa, dane_tlsa

    def test_tlsa(self, mx):
        try:
            has_tlsa = False
            dane_txt = []
            mx_name = '_25._tcp.' + mx
            answers = dns.resolver.query(mx_name, 'TLSA')
            for answer in answers:
                # Even when having TLSA through CNAME, we should receive the TLSA records
                # self.logger.debug("TLSA answer %s " % str(answer))
                has_tlsa = True
                dane_txt.append(str(answer))
        except dns.resolver.NXDOMAIN:
            dane_txt.append('test_tlsa, NXDOMAIN: %s [TLSA]' % mx)
            self.logger.warning(str(dane_txt))
        except dns.resolver.Timeout:
            dane_txt.append('test_tlsa, Timeout: %s  [TLSA]' % mx)
            self.logger.warning(str(dane_txt))
        except dns.resolver.NoAnswer:
            dane_txt.append('test_tlsa, NoAnswer: %s [TLSA]' % mx)
            self.logger.warning(str(dane_txt))
        except dns.exception.DNSException as dex:
            dane_txt.append('test_tlsa, DNSException: %s [TLSA] (%s)' % (mx, str(dex)))
            self.logger.warning(str(dane_txt))
        except Exception as ex:
            dane_txt.append('test_tlsa, GeneralException: %s [TLSA] (%s)' % (mx, str(ex)))
            self.logger.warning(str(dane_txt))
        return has_tlsa, dane_txt

    def execute(self, pem_cert, pem_chain, dane_txt):
        '''
        The execution has to:
            1.- Identify the data of the TLSA record, processing the Usage:
                0 or 2 -> CA cert or Trust Anchor  (target cert requires PKI validation up to the CA or trust Anchor)
                1 or 3 -> End certificate  (1 requires PKI validation, 3 does not )
            2.- Identify wich part of the certificate has to match:
                0 -> Full Certificate (DER binary)
                1 -> SubjectPublicKeyInfo (DER binary)
            3.- Identify the format of the information:
                0 -> Exact match
                1 -> SHA-256
                2 -> SHA-512
            4.- Compare the content of the TLSA record with the TLS cert or CA

        :param pem_cert: The certificate (PEM format) downloaded from the service to test.
        :param pem_chain: List of intermediate certificates (in PEM format)
        :param dane_txt:  txt, the content of the TLSA record (usage, selector, match, value-to-match)
        :return: boolean, True if the TLSA record has been validated, False otherwise.
                 string, error string
        '''
        # RFC 6698
        try:
            rdata = dane_txt.split(' ')
            if len(rdata) == 4:
                (usage, selector, match, content) = rdata
                tlsa_data, usage_error = self.tlsa_usage(int(usage), int(selector), int(match), pem_cert, pem_chain)
                if tlsa_data is not None:
                    for tlsa_match in tlsa_data:
                        if tlsa_match == content:
                            return True, None
                tlsa_failed = 'No match found!'
            else:
                tlsa_failed = "ERROR Parsing TLSA record %s" % dane_txt
            self.logger.warning('DANE Test: %s' % tlsa_failed)
        except Exception as ex:
            tlsa_failed = 'DANE Test: execute matching %s (%s)' % (dane_txt, str(ex))
            self.logger.error(tlsa_failed)
        return False, tlsa_failed

    def tlsa_usage(self, usage, selector, match, pem_cert, pem_chain):
        '''
        This method extracts from the certificate pem_cert the value that must match the content of the TLSA record.

        :param usage: 0-2, specifies the TLSA record uses the CA of the certificate. 1-3 specifies the TLSA record uses
         the certificate itself.
        :param selector: 0 - The whole certificate; 1- The public key
        :param match: 0 - exact Match; 1 - sha256; 2 - sha512;
        :param pem_cert: PEM format, certificate from the service we want to test.
        :param pem_chain: List of intermediate certificates (in PEM format)

        :return: a list of potential matches! List because when usage is 0 or 2, we return all certs in the chain,
                 not only the root CA.
                 string, error message (if any)
        '''
        matches = []
        usage_error = []
        candidates = []

        # Usage 0 and 2 specify the CA or Trusted Anchor that signed the cert
        # extract_ca returns a list of certificates (X509 objects)
        if usage in [0, 2]:
            candidates.extend(self.extract_ca(pem_chain))

        # Usage 1 and 3 specify the cert downloaded fom the server
        #
        elif usage in [1, 3]:
            candidates.append(OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, pem_cert))

        else:
            usage_error.append("tlsa_usage -> usage[%s] is not valid " % str(usage))
            self.logger.warning("tlsa_usage -> usage[%s] is not valid " % str(usage))
            return None, usage_error

        # Once we have the list of certificate/s that should match the TLSA records, we can extract the value
        # that should match the TLSA record.
        try:
            for candidate in candidates:
                match_content, match_content_error = self.tlsa_select_match(selector, match, candidate)
                if match_content is not None:
                    matches.append(match_content)
                else:
                    usage_error.append(match_content_error)
            if len(matches) > 0:
                return matches, None
            else:
                return None, usage_error
        except Exception as ex:
            usage_error.append("ERROR extracting Usage Value! %s" % str(ex))
            self.logger.error("ERROR extracting Usage Value! %s" % str(ex))
            return None, usage_error

    def tlsa_select_match(self, selector, match, certificate):
        '''
        Returns the part (selector 0-1) of the certificate (pem_cert) that needs to match the TLSA record, in the format
        specified in the TLSA record (match 0-1-2)

        :param selector: 0 - The whole certificate; 1- The public key
        :param match: 0 - Exact Match; 1 - sha256; 2 - sha512;
        :param certificate: X509 object, The certificate that has to match the TLSA record
                            (either the service certificate or its CA).

        :return: The part of the certificate specified by the selector, in the format indicated by the match.
                 string, error message (if any)
        '''
        try:
            sslc = OpenSSL.crypto

            # Which part of the certificate will be matched?
            self.logger.debug("Matching Selector %s " % str(selector))
            if selector == 0:
                tmp = sslc.dump_certificate(sslc.FILETYPE_ASN1, certificate)
            elif selector == 1:
                tmp = sslc.dump_publickey(sslc.FILETYPE_ASN1, certificate.get_pubkey())
            else:
                selector_error = "tlsa_select -> selector %s is not valid" % str(selector)
                self.logger.warning(selector_error)
                return None, selector_error

            # How the information is presented?
            self.logger.debug("Matching against %s (0 - exact, 1 - SHA256, 2 - SHA512)" % str(match))
            if match == 0:
                return tmp, None  # Exact match
            elif match == 1:
                return hashlib.sha256(tmp).hexdigest(), None  # SHA-256
            elif match == 2:
                return hashlib.sha512(tmp).hexdigest(), None  # SHA-512
            else:
                selector_error = "tlsa_match -> match %s is not valid" % str(match)
                self.logger.warning(selector_error)
                return None, selector_error
        except Exception as ex:
            selector_error = "tlsa_select_match Generic Exception: %s %s (%s)" % (str(selector), str(ex), str(match))
            self.logger.error(selector_error)
            return None, selector_error

    def extract_ca(self, pem_chain):
        '''
        Returns the whole chain of certificates including the root CA.
        :param pem_chain: List of intermediate certificates (in PEM format)
        :return: the chain of certificates including the root CA.
        '''
        try:
            chain = []
            # Loading the Intermediate certificates.
            issuers = []
            for item in pem_chain:
                cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, item)
                issuers.append(str(cert.get_issuer().get_components()))
                chain.append(cert)

            # Loading the ca
            for ca in self.root_cas:
                subject = str(ca.get_subject().get_components())
                if subject in issuers:
                    chain.append(ca)
                    return chain

            return chain
        except Exception as ex:
            self.logger.error("Dane TLSA extracting CA %s" % str(ex))
            return None
