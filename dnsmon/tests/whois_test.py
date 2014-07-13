__author__ = '3ev0'

import unittest

from dnsmon import whois

class MyTestCase(unittest.TestCase):
    def setUp(self):
        self.whoisclient = whois.WhoisClient()

    # def test_talk_whois(self):
    #     resp = self.whoisclient._talk_whois("whois.iana.org", "nu.nl")
    #     self.assertIn("source:", resp)
    #     self.assertIn("domain:", resp)

    def test_is_ipaddr(self):
        self.assertTrue(self.whoisclient._is_ipaddr("1.23.442.11"))
        self.assertFalse(self.whoisclient._is_ipaddr("a.1.3.4"))
        self.assertFalse(self.whoisclient._is_ipaddr("1.33.41"))

    def test_is_domain(self):
        self.assertTrue(self.whoisclient._is_domain("www.nu.nl"))
        self.assertFalse(self.whoisclient._is_domain("1.2.3.4"))
        self.assertTrue(self.whoisclient._is_domain("nu.n134"))
        self.assertFalse(self.whoisclient._is_domain("nu.123"))
        self.assertTrue(self.whoisclient._is_domain(".info"))

    def test_is_ipaddr(self):
        self.assertTrue(self.whoisclient._is_ipaddr("::1"))
        self.assertTrue(self.whoisclient._is_ipaddr("a00::1111:2"))
        self.assertFalse(self.whoisclient._is_ipaddr("aa::bb::1"))
        self.assertTrue(self.whoisclient._is_ipaddr("a:a:a:a:b:1:2:3"))

    def test_parse_whois_response(self):
        test_response = """
% IANA WHOIS server
% for more information on IANA, visit http://www.iana.org
% This query returned 1 object

refer:        whois.apnic.net

inetnum:      1.0.0.0 - 1.255.255.255
organisation: APNIC
status:       ALLOCATED

whois:        whois.apnic.net

changed:      2010-01
source:       IANA


        """

        wdata = self.whoisclient._parse_whois_response(test_response)
        self.assertEqual(wdata, ([{"refer": "whois.apnic.net"},
                                  {"inetnum":"1.0.0.0 - 1.255.255.255", "organisation": "APNIC", "status": "ALLOCATED"},
                                  {"whois": "whois.apnic.net"},
                                  {"changed": "2010-01", "source": "IANA"}]
        ))

if __name__ == '__main__':
    unittest.main()
