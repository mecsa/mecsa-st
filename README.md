
<p>
<a href="https://mecsa.jrc.ec.europa.eu">
	<img src="https://github.com/mecsa/mecsa-st/blob/master/media/ecjrc_horizontal.png" alt="European Commission - Joint Research Center" align="left" width="300">
</a>
<br><h1>MECSA Standalone Tool</h1><br>
</p>


This is the official repository of **mecsa-st**, the command line version of [My Email Communications Security Assessment (MECSA)](https://mecsa.jrc.ec.europa.eu). MECSA is a public service where users can test the technical capacity of their email providers to protect the security and privacy of email communications.

Mecsa-st is limited to the analysis of the inbound email services (reception of emails by the service provider). An analysis of the outbound service (delivery of emails by the service provider) would require an actual exchange of emails between the domain being assessed and the tool.   

A full assessment of both inbound and outbound email services is available in our free online tool [MECSA](https://mecsa.jrc.ec.europa.eu). Any user with a valid account in an email service can use it to carry out a complete assessment of the capabilities of the service to protect both the reception and delivery of emails.

Given a domain name, e.g. mecsa.dcslab.eu, the mecsa-st tool will execute a series of non-intrusive tests to determine which of the following standards does the tested domain support in its inbound service: [StartTLS](http://www.ietf.org/rfc/rfc3207.txt), [x509 certificate validation](), [SPF](http://www.ietf.org/rfc/rfc7208.txt), [DKIM](http://www.ietf.org/rfc/rfc6376.txt), [DMARC](http://www.ietf.org/rfc/rfc7489.txt), [DANE](http://www.ietf.org/rfc/rfc7671.txt) and [DNSSEC](http://www.ietf.org/rfc/rfc4033.txt).

***Update!***: we have just added a new test for the [MTA-STS](https://www.ietf.org/rfc/rfc8461.txt) standard.

## Getting Started
The mecsa-st tool requires Python 2.7 and the python pip tool.

It has been tested in a Linux environment, although it should also work in windows environments, provided that you specify the parameter *-c* which indicates the file containing the list of trusted CAs as concatenated .pem certificates. By default it takes the file */etc/ssl/certs/ca-certificates.crt*.

Download the mecsa-st repository:

```
git clone https://github.com/mecsa/mecsa-st.git
```

Install prerequisites:

```
pip install pyopenssl dnspython urllib3 pyspf==2.0.12t pydns ipaddr pycryptodome requests
```

Ready to run some tests!

```
cd mecsa-st
python mecsa-st.py <domain-to-test>
```

![screenshot](https://github.com/mecsa/mecsa-st/blob/master/media/execution_sample.gif)


## MECSA Standalone Tests

* **StartTLS**: First we use an DNS request of type MX to obtain all MX records of the domain tested. For each MX, we attempt to establish an SMTP connection and create a TLS communication channel. If successful, we download the server certificate and the intermediate certificates.  
* **x509 Certificate Validation**: To validate the certificates we execute the following tests:
  * Does a trusted Certificate Authority (CA) sign the certificate? the list of trusted CAs is loaded from the file indicated as parameter -c, with default value */etc/ssl/certs/ca-certificates.crt* (file with concatenated .pem certificates)
  * Does the certificate validate the hostname we are connecting to (Full Qualified Domain Name, FQDN)? comparing the MX records against the CN and the SAN.
  * Is the certificate expired?
  * Is the certificate revoked? we check the Revocation List, RCL.
* **SPF**: We check if there is a DNS SPF registry and we use a python library (pyspf) to check the syntax of the SPF registry. 
* **DKIM**: We send a DNS request to the NameServer (NS) of the domain tested, requesting the URL domainkey.*somedomain*. If the NS follows the standard, and the domain supports DKIM, the NS should answer NOERROR, otherwise, it should answer NXDOMAIN.
* **DMARC**: The test on the application of DMARC checks for the existence of a DMARC record, and it does a syntax check on the record found (if any).
* **DANE**: It is validated for each MX. It applies to the incoming servers of email providers, and we test it independently of the results on the DNSSEC test. 
* **DNSSEC**: Given the email domain *domain_test* the DNSSEC assessment requires answering the following questions
  * Is *domain_test* protected by DNSSEC?
  * Are the TXT records of *domain_test* protected by DNSSEC? (optional, if SPF)
  * Are the TXT records of _dmarc.*domain_test* protected by DNSSEC? (optional, if DMARC)
  * Are the Mail Exchanger (MX) records of *domain_test* protected by DNSSEC? 
  * For each MX, is the MX domain name protected by DNSSEC? 
  * For each MX, are the TLSA records of the MX domain name protected by DNSSEC?
* **MTA-STS**: This test is executed in three steps
  * Check for the existence of a DNS record of type TXT on the domain *_mta-sts.domain_test*. If we find a record, we do a syntax check.
  * Download the policy from the URL *mta-sts.domain_test/.well-known/mta-sts.txt* using an ***https*** request. If a policy file is found, we do a syntax check.
  * For each MX hostname, we check if the hostname matches the policy downloaded.  


## License

This project is licensed under the EUPL 1.2 License - see the [LICENSE](LICENSE) file for details

The file [public_suffix_list.dat](https://github.com/mecsa/mecsa-st/blob/master/public_suffix_list.dat) is licensed under the [Mozilla Public License v2.0](https://mozilla.org/MPL/2.0/)

## Links of interest

* [My Email Communications Security Assessment (MECSA)](https://mecsa.jrc.ec.europa.eu)
* [Internet NL](https://internet.nl/)
