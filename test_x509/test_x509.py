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


import OpenSSL.crypto
from cache_x509 import CacheX509
from datetime import date
from datetime import datetime


class TestCertificate():

    def __init__(self, logger, root_cas, cache_x509=None):
        '''
        Initialization of the class that tests the x509 certificates.

        :param logger: instance of a 'logger' class
        :param root_cas: list of default Root-CAs certificates
        :param cache_x509: object used to fetch and cache the Revocation Lists
        '''

        self.logger = logger
        self.cas = root_cas
        if cache_x509 is None:
            self.cache_x509 = CacheX509(logger)
        else:
            self.cache_x509 = cache_x509

    def test_certificate(self, row):
        '''
        Given an x509 certificate in pem format, and the domain it should validate, fqdn. It will test:

        1.- If the certificate contains the FQDN.
        2.- If the certificate is valid, not expired by date.
        3.- If the certificate is in a Revocation List
        4.- If the certificate is signed by a Certificate Authority (CA)

        :param row, dictionary
                { ir_mx, hostname of the MX
                  ir_certificate, certificate of the MX server (pem format)
                  ir_certificate_chain, list of intermediate certificates (pem format)
                  -------- The following values are filled in this function ------
                  ir_certificate_fqdn_valid, booelan - MX matches the CN or SAN field in the server certificate?
                  ir_certificate_date_valid, booelan - is the certificate valid 'today'?
                  ir_certificate_revocated, booelan - is the certificate in a revocation list?
                  ir_certificate_ca_valid, booelan - is the certificate signed by a trusted Root CA
                  }
        :return: boolean, certificate passed all 4 tests? True/False
                 String, error (if any)
        '''
        try:
            pem = row['ir_certificate']
            pem_chain = row['ir_certificate_chain']
            fqdn = row['ir_mx']

            # 1.-
            row['ir_certificate_fqdn_valid'] = self.fqdn_valid(pem, fqdn)
            # 2.-
            row['ir_certificate_date_valid'] = self.date_valid(pem)
            # 3.-
            row['ir_certificate_revocated'], crl_error = self.test_rcl(pem)
            # 4.-
            row['ir_certificate_ca_valid'], ca_error = self.ca_verification_test(pem, pem_chain, self.cas)

            if row['ir_certificate_fqdn_valid'] and row['ir_certificate_date_valid'] and not row['ir_certificate_revocated'] and row['ir_certificate_ca_valid']:
                return True, None
            else:
                return False, None
        except Exception as ex:
            ca_error = 'Error validating certificate for MX %s (%s)' % (row['ir_mx'], str(ex))
            self.logger.warning(ca_error)
            return False, ca_error

    def fqdn_valid(self, pem, mx):
        '''
        Tests if the hostname of the MX record (mx) matches either the Subject['CN'] or the SubjectAltName
        (exact match or wildcard match)

        :param pem:  certificate to test, in pem format
        :param mx: hostname to match in the certificate
        :return: True or False (match or do not match)
        '''
        try:
            cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, pem)
            extensions = []
            for i in range(cert.get_extension_count()):
                if cert.get_extension(i).get_short_name() == "subjectAltName":
                    extensions.append(cert.get_extension(i))
            components = dict(cert.get_subject().get_components())
            hostname = mx.lower()
            if 'CN' in components:
                if components['CN'].lower() == hostname:
                    self.logger.debug('*** CN Exact MATCH!: %s - %s' % (hostname, components['CN']))
                    return True
                elif '*' in components['CN']:
                    tests = len(hostname.split('.'))
                    for index in range(1, tests):
                        sample = '*' + hostname[hostname.index('.'):]
                        hostname = sample[2:]
                        if sample == components['CN']:
                            self.logger.debug('*** CN Wildcard MATCH!: %s - %s' % (sample, components['CN']))
                            return True
            for extension in extensions:
                alt_name = extension.__str__()
                if hostname in alt_name:
                    self.logger.debug('*** SAN Exact MATCH!: %s - %s' % (hostname, alt_name))
                    return True
                else:
                    tests = len(hostname.split('.'))
                    for index in range(1, tests):
                        sample = '*' + hostname[hostname.index('.'):]
                        hostname = sample[2:]
                        if sample in alt_name:
                            self.logger.debug('*** SAN Wildcard MATCH!: %s - %s' % (sample, alt_name))
                            return True
        except Exception as ex:
            self.logger.warning("certificate testing FQDN MX: %s (%s)" % (mx, str(ex)))
        return False

    def date_valid(self, pem):
        '''
        Tests if the certificate is valid Today, i.e. if it is not expired.
        (certificate not expired AND today >= validfrom AND today <= valid-to ? True:False)

        :param pem:  certificate to test in pem format
        :return: expired:False || not_expired:True
        '''
        try:
            cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, pem)
            subject = str(cert.get_subject())
            current = date.today()
            expired = cert.has_expired()
            try:
                valid_from = datetime.strptime(cert.get_notBefore(), "%Y%m%d%H%M%SZ")
                valid_to = datetime.strptime(cert.get_notAfter(), "%Y%m%d%H%M%SZ")
            except Exception as ex:
                self.logger.warning("Error parsing dates for cert: %s (%s)" % (subject, str(ex)))
                return False
            if (current >= valid_from.date()) and (current <= valid_to.date()) and not expired:
                return True
        except Exception as ex:
            self.logger.warning("Certificate Testing Expiration Date (%s)" % str(ex))
        return False

    def init_row(self, hash=None, pem=None):
        '''
        Initialization of the dictionary of values.

        :param hash: md5 hash of the certificate
        :param pem: certificate in pem format

        :return: a dictionary of keyword, value, regarding the certificate.

        cert_hash ------------- String, md5 hash of the certificate (.pem)
        cert_pem -------------- String, certificate in .pem format
        cert_keysize ---------- int, Size of the public key (bits)
        cert_algorithm -------- String, algorithm used to generate the certificate
        cert_is_ca ------------ Boolean, is it a Certificate Authority? True:False
        cert_is_selfsigned ---- Boolean, is the certificate Self-Signed? True:False
        cert_subject ---------- String, Subject field of the Certificate
        cert_subject_cn ------- String, Common Name (CN) from the Subject Field
        cert_subject_o -------- String, Organization (O) from the Subject Field
        cert_issuer ----------- String, Issuer field of the Certificate
        cert_issuer_cn -------- String, Common Name (CN) from the Issuer Field
        cert_issuer_o --------- String, Organization (O) from the Issuer Field
        cert_altname ---------- String, Subject Alternative Name (SAN) field of the certificate
        cert_valid_ca --------- Boolean, Certificate is signed by a trusted Certificate Authority (CA)? True:False
        cert_ca_error --------- String, error (if any) while validating the certificate signature
        cert_fqdn_valid ------- Boolean, Full Qualified Domain Name of the server matches either the CN or the SAN?
        cert_expired ---------- Boolean, Has the certificate expired? True:False
        cert_revocated -------- Boolean, Is the certificate in the Revocation List (RCL)? True:False
        cert_revocated_error -- String, error (if any) while checking the RCL
        cert_rcl_urls --------- String, URL where to download the RCL
        cert_valid_from ------- String, Date the certificate was generated
        cert_valid_to --------- String, Date the certificate will expire
        cert_valid_dates ------ String, 'From # To' -> '--/--/-- --:--:-- # --/--/-- --:--:--'


        '''
        row = {}
        row['cert_hash'] = hash
        row['cert_pem'] = pem
        row['cert_keysize'] = 0
        row['cert_algorithm'] = None
        row['cert_is_ca'] = False
        row['cert_is_selfsigned'] = False
        row['cert_subject'] = None
        row['cert_subject_cn'] = None
        row['cert_subject_o'] = None
        row['cert_issuer'] = None
        row['cert_issuer_cn'] = None
        row['cert_issuer_o'] = None
        row['cert_altname'] = None
        row['cert_valid_ca'] = False
        row['cert_ca_error'] = False
        row['cert_fqdn_valid'] = False
        row['cert_expired'] = False
        row['cert_revocated'] = False
        row['cert_revocated_error'] = None
        row['cert_rcl_urls'] = None
        row['cert_valid_from'] = None
        row['cert_valid_to'] = None
        row['cert_valid_dates'] = '--/--/-- --:--:-- # --/--/-- --:--:--'
        return row

    def parse_date(self, input):
        '''
        converts the input date in the format 'YYYY-mm-dd HH:mm:ss'.

        :param input: string representing the date extracted from a certificate
        :return: a date with format 'YYYY-mm-dd HH:mm:ss'
        '''
        try:
            year = input[:4]
            month = input[4:6]
            day = input[6:8]
            hour = input[8:10]
            min = input[10:12]
            sec = input[12:14]
            return year + '-' + month + '-' + day + ' ' + hour + ':' + min + ':' + sec
        except Exception as ex:
            self.logger.error("Parsing Date: %s %s (%s)" % (input, str(input), str(ex)))
            return 'YYYY-mm-dd HH:mm:ss'

    def test_rcl(self, pem):
        '''
        For a certificate, pem, it will  recover its revocation list from 'crlDistributionPoints', and check
        if the serial number of the certificate is in the list.

        :param pem: certificate in pem format
        :return: Boolean, pem is revoked? True:False
                 String, error (if any)
        '''
        try:
            has_crl = False
            sslc = OpenSSL.crypto
            cert = sslc.load_certificate(sslc.FILETYPE_PEM, pem)
            subject = str(cert.get_subject())
            serial_number = int(cert.get_serial_number())
            errors = []
            for i in range(cert.get_extension_count()):
                if cert.get_extension(i).get_short_name() == "crlDistributionPoints":
                    has_crl = True
                    content = cert.get_extension(i).__str__().split('\n')
                    crl_uris = []
                    for line in content:
                        if ('URI:' in line) and ('.crl' in line):
                            try:
                                begin_line = line.index("URI:") + 4
                                end_line = line.index(".crl") + 4
                                crl_uris.append(line[begin_line: end_line].strip())
                            except Exception as ex:
                                error_msg = "test_rcl-> parsing line %s (%s)" % (line, str(ex))
                                self.logger.warning(error_msg)
                                errors.append(error_msg)
                    for crl_server in crl_uris:
                        try:
                            crl_pem = self.cache_x509.select_revocation_list(crl_server)
                            if crl_pem is not None:
                                crl = sslc.load_crl(sslc.FILETYPE_PEM, crl_pem)
                                revoked_serials = crl.get_revoked()
                                for serial in revoked_serials:
                                    int_serial = int(serial.get_serial(), 16)
                                    if serial_number == int_serial:
                                        return True, None
                            else:
                                errors.append("MISSING revocation list. %s " % str(crl_server))
                        except Exception as ex:
                            error_msg = "Recovering CRL list %s (%s)" % (str(crl_server), str(ex))
                            self.logger.warning(error_msg)
                            errors.append(error_msg)
            if has_crl is False:
                errors.append("MISSING crlDistributionPoints, Subject %s" % subject)
            if len(errors) > 0:
                crl_error = '; '.join(errors)
            else:
                crl_error = None
        except Exception as ex:
            error_msg = "REVOCATION test for cert: %s (%s)" % (subject, str(ex))
            self.logger.error(error_msg)
            errors.append(error_msg)
        return False, crl_error

    def ca_verification_test(self, pem, pem_chain, list_cas):
        '''
        Function to verify if the certificate is correctly signed by a CA.

        :param pem, certificate to verify (.pem format)
        :param pem_chain, list of intermediate certificates (.pem format)
        :param list_cas, list of Root CAs certificates (.cert format)
        :return: boolean, pem is signed by a trusted CA? True:False
                 string, errors (if any)
        '''

        try:
            test_certificate = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, pem)
        except Exception as ex:
            ca_verification_error = "PEM2x509 failed: " + str(ex)
            self.logger.error(ca_verification_error)
            return False, ca_verification_error
        test_issuer = str(test_certificate.get_issuer().get_components())
        test_subject = str(test_certificate.get_subject().get_components())

        intermediate_certs = []
        try:
            if pem_chain is not None:
                for cert in pem_chain:
                    if "-----BEGIN CERTIFICATE-----" in cert:
                        intermediate_certs.append(OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert))
            else:
                self.logger.warning("Empty Intermediate certs Chain.")
        except Exception as ex:
            self.logger.warning("Building Intermediate certs Chain (%s)" % str(ex))

        # Now we have test_certificate + certificates (intermediate and CA certs).
        # We will delete all self-signed certificates (if any) from the intermediate list.
        # In the end, we want to have:
        # storeX509 = test_certificate + certificates (intermediate) + CA certificates (Root CAs)
        if len(intermediate_certs) > 0:
            for candidate in intermediate_certs:
                if self.test_self_signed(candidate):
                    intermediate_certs.remove(candidate)
        else:
            # This could be an indication that test_certificate is self-signed
            if self.test_self_signed(test_certificate):
                self.logger.warning("Certificate is Self-Signed! subject: %s, issuer: %s" % (test_subject, test_issuer))
                return False, "MX Certificate is Self-Signed!"

        # Now we have: test_certificate + certificates (intermediate) + 'CAs' (X509Store).
        try:
            # create a x509 Store with the chain of certificates.
            store = OpenSSL.crypto.X509Store()
            # add the CAs to the store (.cert format)
            for ca in list_cas:
                store.add_cert(ca)
            # add the intermediate certificates to the store (.cert format)
            for cert in intermediate_certs:
                store.add_cert(cert)
        except Exception as ex:
            ca_verification_error = "xv509Store Creation. issuer: %s (%s)" % (test_issuer, str(ex))
            self.logger.warning(ca_verification_error)
            return False, ca_verification_error

        # create a x509 Store context, with the certificate chain and the certificate we want to test.
        try:
            store_ctx = OpenSSL.crypto.X509StoreContext(store, test_certificate)
            store_ctx.verify_certificate()
            self.logger.debug("PASSED CA validation subject: %s, issuer: %s" % (test_subject, test_issuer))
            return True, None
        except Exception as ex:
            ca_verification_error = "FAILED CA validation! subject: %s, issuer: %s (%s)" % (test_subject, test_issuer, str(ex))
            self.logger.warning(ca_verification_error)
            return False, ca_verification_error

    def test_self_signed(self, certificate):
        '''
        Given a certificate, it will check if it is self-signed.

        :param certificate: certificate we want to test. cert format (Not PEM!)
        :return: Boolean, self-signed? True:False
        '''
        try:
            store_self_signed = OpenSSL.crypto.X509Store()
            store_self_signed.add_cert(certificate)
            issuer = str(certificate.get_issuer().get_components())
            try:
                store_self_signed_ctx = OpenSSL.crypto.X509StoreContext(store_self_signed, certificate)
                store_self_signed_ctx.verify_certificate()
                return True
            except Exception as ex:
                self.logger.debug("certificate is NOT self-signed %s (%s)" % (issuer, str(ex)))
        except Exception as ex:
            self.logger.error("Testing certificate self-signed (%s)" % str(ex))
        return False
