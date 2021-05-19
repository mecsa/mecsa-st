
<p>
<a href="https://mecsa.jrc.ec.europa.eu">
	<img src="https://github.com/mecsa/mecsa-st/blob/master/media/ecjrc_horizontal.png" alt="European Commission - Joint Research Center" align="left" width="300">
</a>
<br><h1>MECSA Standalone Tool</h1><br>
</p>


This is the official git repository of **mecsa-st**, the command line version of [My Email Communications Security Assessment (MECSA)](https://mecsa.jrc.ec.europa.eu). MECSA is a public service where users can test the technical capacity of their email providers to protect the security and privacy of email communications.

This command line version of the [MECSA](https://mecsa.jrc.ec.europa.eu) service engine, mecsa-st, is limited to the analysis of the inbound email services (the analysis of the security standards supported by the email provider to receive email from other email providers). Further analysis of the security standards used to protect email delivery (outbound email services) is not supported, as this would require the reception of an email sent by the email provider tested.

A full assessment of both inbound and outbound email services is available in our free online tool [MECSA](https://mecsa.jrc.ec.europa.eu). This online service allows any user, with a valid email account in an email service, to carry out a complete assessment of the capabilities of that email provider, to protect both the reception and delivery of emails.

mecsa-st, on the other hand, only requires the domain name of the email service to be analysed, which is given as a command line argument. A series of non-intrusive tests will be executed to determine which of the following security standards are properly supported by the email provider. 

* [StartTLS](http://www.ietf.org/rfc/rfc3207.txt)
* [RequireTLS](https://www.ietf.org/rfc/rfc8689.txt)
* [Analysis of signatures, chain of trust and validity of x509 certificates]()
* [SPF](http://www.ietf.org/rfc/rfc7208.txt)
* [DKIM (presence estimation only)](http://www.ietf.org/rfc/rfc6376.txt)
* [DMARC](http://www.ietf.org/rfc/rfc7489.txt)
* [DANE](http://www.ietf.org/rfc/rfc7671.txt) 
* [DNSSEC](http://www.ietf.org/rfc/rfc4033.txt).
* [MTA-STS](https://www.ietf.org/rfc/rfc8461.txt)

The objective of these protocols is to protect the reception of emails.

***Update!*** the new version of mecsa-st released on 20/05/2021 contains the following changes:

* Checks the presence of the SMTP Require TLS option when sending a message

***Update!*** We have recently published a paper in the [IEEE Access](https://ieeeaccess.ieee.org/) peer reviewed journal.
You can find it int the [EU Science Hub](https://ec.europa.eu/jrc/en/publication/what-email-servers-can-tell-johnny-empirical-study-provider-provider-email-security):

Please use the following bibtex entry to cite the paper:
```
@ARTICLE{Kambourakis2020,
  author={G. {Kambourakis} and G. {Draper} and I. {Sanchez}},
  journal={IEEE Access}, 
  title={What Email Servers Can Tell to Johnny: An Empirical Study of Provider-to-Provider Email Security}, 
  year={2020},
  volume={8},
  pages={130066-130081},}
```

***Update!*** the new version of mecsa-st released on 20/03/2020 contains the following changes:

* Upgraded to python3
* Support for the analysis of MTA-STS
* Added support for additional DNSSEC algorithms
* New scoring function considering the specific policies deployed in the SPF and DMARC standards. 

## Getting Started
The mecsa-st tool requires Python 3 and the following python libraries: *py3dns, pyopenssl, urllib3, pyspf, ipaddr, pycryptodome, requests, ECPy* and the new version of *dnspython* (available in git).

Mecsa-st has been tested in a Linux environment, although it should also work in windows and mac environments, provided that the parameter -c is used to indicate the file containing the list of trusted CAs as concatenated .pem certificates. By default, the file is taken from */etc/ssl/certs/ca-certificates.crt*.

**Installation Steps**

Clone the official mecsa-st git repository:

```
git clone https://github.com/mecsa/mecsa-st.git
```
Install python3
```
sudo apt-get update
sudo apt-get install python3 python3-pip python3-venv 
```
Create and activate a Python 3 Virtual Environment to run mecsa-st
```
cd mecsa-st
python3 -m venv mecsa-st_venv
source mecsa-st_venv/bin/activate
```
Install required libraries using pip
```
pip install wheel
pip install py3dns pyopenssl urllib3 pyspf ipaddr pycryptodome requests ECPy
```

Install the latest version of dnspython from the official git repository
```
git clone https://github.com/rthalley/dnspython.git
cd dnspython
python setup.py install
```

**Usage**

Quick usage (remember to activate the python3 venv):

```
(mecsa-st_venv) python mecsa-st.py <domain-to-test>
```

Full usage syntax:

```
usage: mecsa-st.py [-h] [-l LOG] [-c CERTIFICATES] domain

MECSA Standalone Test

positional arguments:
  domain                domain to test

optional arguments:
  -h, --help            show this help message and exit
  -l LOG, --log LOG     specify path and name of logfile. Default is mecsa-st.log
  -c CERTIFICATES, --certificates CERTIFICATES specify path from where to load the CA certificates. Default is '/etc/ssl/certs/ca-certificates.crt'
```

![screenshot](https://github.com/mecsa/mecsa-st/blob/master/media/execution_sample.gif)


## Security analysis carried about by MECSA-ST

* **StartTLS**: A DNS request is performed to retrieve all MX records of the domain tested. For each MX, an SMTP connection is established and a TLS communication channel is negotiated. If successful, the provided server certificate and the intermediate certificates are downloaded.
* **RequireTLS**: During the establishment of the SMTP connection (see above) it is checked whether the REQUIRETLS SMTP service extension is announced (in the form of the EHLO keyword value "REQUIRETLS"). This extension specifies that a message must be sent over a TLS communication channel.
* **x509 Certificate Validation**: The following tests are executed to validate the x509 certificates:
  * Full certificate chain of trust validation (digital signatures).
  * Check that root CA signing the certificate is trusted. The list of trusted CAs is loaded from the file indicated as parameter -c. If no file is specific, the default is */etc/ssl/certs/ca-certificates.crt* (file with concatenated .pem certificates)
  * Check that the CN or SAN of the certificate matches the FQDN (Full Qualified Domain Name) it refers to (MX records). 
  * Check that the certificate is not expired. 
  * Check that the certificate has not been revoked (CLR).
* **SPF**: Validate that a DNS SPF record exists, test that the syntax is correct and check the defauk policy value (parameter "*all*"). 
* **DKIM**: Check for evidence of the existence of a DKIM DNS record by sending a DNS request to the authoritative DNS servers for the domain tested (NS records), requesting the URL domainkey.*somedomain*. If the NS servers follow the DNS standard and the domain supports DKIM, the NS should answer NOERROR, otherwise, it should answer NXDOMAIN. 
* **DMARC**: Validate that a DNS DMARC record exists, test that the syntax is correct and check the policy value (parameter *p=*).
* **DANE**: Validation of DANE records for each MX (if they exist). This test is independent from the DNSSEC test. 
* **DNSSEC**: Given the email domain *domain_test* the DNSSEC assessment requires answering the following questions
  * Is *domain_test* protected by DNSSEC?
  * Are the TXT records of *domain_test* protected by DNSSEC? (only if SPF is present)
  * Are the TXT records of _dmarc.*domain_test* protected by DNSSEC? (only if DMARC is present)
  * Are the Mail Exchanger (MX) records of *domain_test* protected by DNSSEC? 
  * For each MX, is the MX domain name protected by DNSSEC? 
  * For each MX, are the TLSA records of the MX domain name protected by DNSSEC?
* **MTA-STS**: This validation is executed in three steps
  * Validate the existence and syntax of a DNS record of type TXT on the domain *_mta-sts.domain_test*.
  * Retrieve the policy from the URL *mta-sts.domain_test/.well-known/mta-sts.txt* using an ***https*** request and perform a syntax check.
  * Validate that for each MX hostname the hostname matches the policy retrieved.  

## Scoring
In addition to the technical results of the analysis, mecsa-st provides an accessible and easy to understand summary of the results scoring the email service analysed in the following categories: confidentiality, authenticity (protection against phishing and identity theft) and integrity.

* **Confidentiality**: Evaluates the capacity to protect the incoming/outgoing email communications, from being read by third parties that could be listening the communication channel or impersonating the recipient. The protocols that [MECSA](https://mecsa.jrc.ec.europa.eu) uses to score this category are StartTLS, x509, DANE, DNSSEC and MTA-STS.

* **Phishing and Identity Theft**: Measures the capacity of email providers to facilitate the identification of email messages sent from unauthorized third parties. In particular, [MECSA](https://mecsa.jrc.ec.europa.eu) uses SPF, DKIM, DMARC, and DNSSEC to evaluate this category.

* **Integrity**: Evaluates the capacity to facilitate the detection of modified messages (content received differs from content sent), and the generation of evidence that messages have not been modified. The security standards that [MECSA](https://mecsa.jrc.ec.europa.eu) applies to score this category are DKIM, DMARC and DNSSEC

The score value assigned to each category depends on which email security protocols are supported by the email provider tested, the specific way in which they are implemented and the policies deployed. This relation can be modified through a .json file (commons/scoring.json). The specific score value will be calculated on the basis of the combination of supported protocols and policy evaluations described in this file.

It is important to note that given the limitations of mecsa-st, the command line version of [MECSA](https://mecsa.jrc.ec.europa.eu), the score values obtained here will not be aligned by those provided in the online [MECSA](https://mecsa.jrc.ec.europa.eu). As explained above in this README, this is because the online [MECSA](https://mecsa.jrc.ec.europa.eu) service provides a more exhaustive security analysis of the communications considering not only the email inbound services (email reception) but also the outbound ones (email delivery).  

## License

This project is licensed under the EUPL 1.2 License - see the [LICENSE](LICENSE) file for details

The file [public_suffix_list.dat](https://github.com/mecsa/mecsa-st/blob/master/public_suffix_list.dat) is licensed under the [Mozilla Public License v2.0](https://mozilla.org/MPL/2.0/)


## Links of interest

* [My Email Communications Security Assessment (MECSA)](https://mecsa.jrc.ec.europa.eu)
* [Internet NL](https://internet.nl/)
* [Webcheck PT](https://webcheck.pt/)
* [TU Delft research study](https://www.email-security-scans.org/)
