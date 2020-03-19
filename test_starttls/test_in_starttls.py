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

import hashlib
import struct
import socket
from OpenSSL import SSL
import OpenSSL
import smtplib
import dns.resolver


local_hostname = 'mecsa.dcslab.eu'
success_codes = [220]


class TestStartTLS(object):

    def __init__(self, logger):
        self.logger = logger

    def init_test(self, domain):
        '''
        For a domain name it will request the MX records, and for each MX record
        the list of records A published.

        :param domain:  email domain name we are evaluating
        :return: list of parameters
                    'mx'         MX hostname, if the domain has MX records,
                                 otherwise it returns the same domain name
                    'priority'   priority of that MX
                    'ipv4'       ip address of the MX
                    'is_mx'      boolean: domain has MX records?True:False
                                 (if False, 'mx' will be the same domain)
        '''
        tests = []
        try:
            has_mx_records, mx_records, mx_error = self.fecth_mx(domain)
            if not has_mx_records:
                self.logger.warning('Domain %s does NOT have MX records!' % domain)
                mx_records = []
                mx_record = {}
                mx_record['mx'] = domain
                mx_record['priority'] = '10'
                mx_records.append(mx_record)
            for mx in mx_records:
                has_a_records, a_records, a_error = self.fecth_a(mx['mx'])
                if has_a_records:
                    for ipv4 in a_records:
                        test = {}
                        test['mx'] = mx['mx']
                        test['priority'] = mx['priority']
                        test['ipv4'] = ipv4
                        test['is_mx'] = has_mx_records
                        tests.append(test)
        except Exception as ex:
            self.logger.error('General Exception init_test_starttls %s (%s)' % (domain, str(ex)))
        return tests

    def supports_starttls(self, row):
        '''
        Given an ip adddress (ir_mx_ipv4) of an MX server, it will:
         1.- attempt to connect to port 25
         2.- check the support for STARTTLS
         3.- create an SMTP TLS connection.

        :param row:  dictionary of values:
                     'ir_mx', 'ir_mx_ipv4', 'ir_mx_priority' must be set.

                     The following will be set inside the function:
                      'ir_smtp_success', boolean - indicates if the SMTP connection was succsessful
                      'ir_banner', string - the reponse code and the content of the banner received from the MX
                      'ir_esmtp_features', string - the list of ESMTP features supported (announced) by the MX
                      'ir_starttls', boolean - indicates if the MX supports STARTTLS
                      'ir_starttls_announced', boolean - indicates if STARTTLS is announced in the ESMTP list
                      'ir_starttls_enc', string - cipher negotiated to create the TLS connection
                      'ir_certificate', string - certificate of the MX in .pem format
                      'ir_certificate_error', string - description of errors (if any) occurred while
                                                       downloading the certificates.
                      'ir_certificate_hash', string - hash of the certificate of the MX
                      'ir_certificate_chain', string - intermediate certificates concatenated in pem format
                      'ir_error', string - description of errors occurred while testing STARTTLS, if any.

        :return: boolean - MX in ir_mx_ipv4 supports StartTLS? True/False

        '''

        # 1.- We create an SMTP connection and we check that it supports ESMTP.
        #     (if ESMTP is supported, we check if STARTTLS is announced)
        (banner, connection, error) = self.get_smtp_connection(row['ir_mx_ipv4'])
        if error is not None:
            row['ir_error'] = error
            self.logger.debug('SMTP connection exception %s (%s)' % (row['ir_mx'], error))
            return row
        self.logger.debug('processing STARTTLS... for MX %s, IPv4 %s' % (row['ir_mx'], row['ir_mx_ipv4']))
        row['ir_banner'] = banner
        row['ir_smtp_success'] = True

        try:
            (c, msg) = connection.ehlo()
            esmtp_support = (200 <= c <= 299)
            if not esmtp_support:
                row['ir_error'] = "SMTP server does not support EHLO (%s)" % msg
                return row
            row['ir_esmtp_features'] = str(connection.esmtp_features)
            self.logger.debug('ESMTP features announced: (%s)' % row['ir_esmtp_features'])
            row['ir_starttls_announced'] = connection.has_extn("starttls")
        except Exception as ex:
            row['ir_error'] = "EHLO Communication Exception (%s)" % str(ex)
            self.logger.error(row['ir_error'])
            return row

        # 2.- We test the STARTLS command and if supported we download the certificates
        # from the server.
        self.logger.debug("Starting STARTTLS...")
        try:
            (resp, reply) = connection.docmd("STARTTLS")
            self.logger.debug("STARTTLS reply: %s" % reply)
            if resp != 220:
                row['ir_error'] = "STARTTLS command unsuccessful (%s)" % reply
                self.logger.debug(row['ir_error'])
                return row
            self.logger.debug("%s, %s  Supports StartTLS" % (row['ir_mx'], row['ir_mx_ipv4']))
            row['ir_starttls'] = self.download_certificate(row, connection)
        except Exception as smtpe:
            row['ir_error'] = "ERROR processing STARTTLS %s (%s)" % (row['ir_mx'], str(smtpe))
            self.logger.error(row['ir_error'])
        return row

    def download_certificate(self, row, connection):
        '''
        using 'connection', it will  try to download the certificate from the server, and the
        list of intermediate certificates.

        :param:  connection, SMTP connection
        :param:  row, dictionary of values:
                     'ir_mx'  must be set (used to match with the FQDN).

                     The following will be set inside the function:
                      'ir_certificate', string - certificate of the MX in .pem format
                      'ir_certificate_error', string - description of errors (if any) occurred while
                                                       downloading the certificates.
                      'ir_certificate_hash', string - hash of the certificate of the MX
                      'ir_certificate_chain', string - intermediate certificates concatenated in pem format

        :return: boolean - certificate downloaded? True/False
        '''

        has_cert = False
        try:
            tcp_socket = connection.sock
            tcp_socket.setblocking(1)
            context = SSL.Context(SSL.SSLv23_METHOD)
            context.set_cipher_list(b'ALL')
            connection = OpenSSL.SSL.Connection(context, tcp_socket)
            connection.set_connect_state()
            timeval = struct.pack('ll', 30, 100)
            tcp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVTIMEO, timeval)
            connection.do_handshake()
            has_cert = True
            row['ir_starttls_enc'] = "Using %s with cipher %s (%d bits)" % (connection.get_cipher_version(),
                                                                            connection.get_cipher_name(),
                                                                            connection.get_cipher_bits())

            # Obtain the server certificate
            mx_certificate = connection.get_peer_certificate()
            row['ir_certificate'] = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, mx_certificate)
            row['ir_certificate_hash'] = hashlib.md5(row['ir_certificate']).hexdigest()

            # Obtain the intermediate server certificates
            intermediate_certs = []
            chain = connection.get_peer_cert_chain()
            for (idx, cert) in enumerate(chain):
                self.logger.debug("Certificate: %s" % cert.get_subject())
                pem_cert = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
                if pem_cert != row['ir_certificate']:
                    intermediate_certs.append(pem_cert)
            if len(intermediate_certs) > 0:
                row['ir_certificate_chain'] = intermediate_certs
        except Exception as ex:
            row['ir_certificate_error'] = ('ERROR Downloading certificate (%s)' % str(ex))
            self.logger.error(row['ir_certificate_error'])
        return has_cert

    def get_smtp_connection(self, ipv4):
        '''
        Creates an SMTP connection with the MX on the IP address ipv4.

        :param ipv4: IP address of the SMTP server to test.
        :return banner: string - response code + content of the banner received from the MX when creating a connection
                connection: SMTP connection - the connection created with the MX server
                error: string - description of an error occurred (if any) during the creation of the SMTP connection
        '''

        try:
            connection = smtplib.SMTP(timeout=35, local_hostname=local_hostname)
            (c, msg) = connection.connect(ipv4)
            banner = "%d %s " % (c, msg)
            self.logger.debug("Server response: %s" % banner)
            if c not in success_codes:
                error = banner
                self.logger.debug('SMTP connection failed: (code!=220) ' + ipv4 + ' ' + error)
                return None, None, error
        except Exception as ex:
            error = 'SMTP  Connection Exception %s (%s)' % (ipv4, str(ex))
            self.logger.error(error)
            return None, None, error
        return banner, connection, None

    def fecth_a(self, mx):
        '''
        Given a hostname (mx), it will return the A records.

        :param:  mx string, Domain name tested
        :return: (boolean, String[], String)
                  MX has A record? True:False
                  List of A records for mx
                  Errors in the query
        '''

        try:
            has_ipv4 = False
            a_error = None
            ips = []
            self.logger.debug('sending DNS A request for MX ' + mx)
            answers = dns.resolver.query(mx, 'A')
            self.logger.debug(mx + ' has ' + str(len(answers)) + ' IPv4 addresses')
            for ip in answers:
                try:
                    ipv4 = ip.address
                    ips.append(ipv4)
                except Exception as ex:
                    self.logger.error("Error fetching A records " + mx + " " + str(ex))
            if len(ips) > 0:
                has_ipv4 = True
        except dns.resolver.NXDOMAIN:
            a_error = 'NXDOMAIN: ' + mx + ' [A]'
            self.logger.warning(a_error)
        except dns.resolver.Timeout:
            a_error = 'Timeout: ' + mx + '  [A]'
            self.logger.warning(a_error)
        except dns.resolver.NoAnswer:
            a_error = 'NoAnswer: ' + mx + ' [A]'
            self.logger.warning(a_error)
        except dns.exception.DNSException as dex:
            a_error = 'DNSException: ' + mx + ' [A] ' + str(dex)
            self.logger.warning(a_error)
        except Exception as ex:
            a_error = str(ex)
            self.logger.warning(a_error)
        return has_ipv4, ips, a_error

    def fecth_mx(self, domain):
        '''
        Given a domain, it will return the MX records.

        :param:  string domain, Domain name tested
        :return: (boolean, String[], String)
                  .domain has MX record? True:False
                  .List of MX records for domain
                  .Errors in the query
        '''
        try:
            has_mx = False
            mx_error = None
            mx_records = []
            self.logger.debug('sending DNS MX request for domain %s' % domain)
            answers = dns.resolver.query(domain, 'MX')
            self.logger.debug('%s has %s MX records' % (domain, str(len(answers))))
            for answer in answers:
                try:
                    mx_record = {}
                    mx_record['mx'] = answer.exchange.to_text(True)
                    mx_record['priority'] = str(answer.preference)
                    mx_records.append(mx_record)
                except Exception as gex:
                    self.logger.warning("Error fetching MX for domain %s (%s)" % (domain, str(gex)))
            if len(mx_records)>0:
                has_mx = True
        except dns.resolver.NXDOMAIN:
            mx_error = 'fetch_mx NXDOMAIN: %s [MX]' % domain
            self.logger.warning(mx_error)
        except dns.resolver.Timeout:
            mx_error = 'fetch_mx Timeout: %s [MX]' % domain
            self.logger.warning(mx_error)
        except dns.resolver.NoAnswer:
            mx_error = 'fetch_mx NoAnswer:  %s  [MX]' % domain
            self.logger.warning(mx_error)
        except dns.exception.DNSException as dex:
            mx_error = 'fetch_mx DNSException:  %s  [MX] (%s)' % (domain, str(dex))
            self.logger.warning(mx_error)
        except Exception as ex:
            mx_error = 'fetch_mx General Exception:  %s  [MX] (%s)' % (domain, str(ex))
            self.logger.warning(mx_error)
        return has_mx, mx_records, mx_error
