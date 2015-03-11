
import unittest
from traceroute import *

class MyTestCase(unittest.TestCase):
    def test_ip_checker_ok1(self):
        self.assertEqual(isIP("8.8.8.8"), True)

    def test_ip_checker_ok(self):
        self.assertEqual(isIP("123.1.3.12"), True)

    def test_ip_checker_wrong1(self):
        self.assertEqual(isIP("1.3.12"), False)

    def test_ip_checker_wrong2(self):
        self.assertEqual(isIP("a.1.3.12"), False)

    def test_ip_checker_wrong2(self):
        self.assertEqual(isIP("google.com"), False)

    def test_ip_checker_wrong3(self):
        self.assertEqual(isIP("12,13,3,12"), False)





if __name__ == '__main__':
    unittest.main()
