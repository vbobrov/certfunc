#!/usr/bin/env python3
import unittest
from certfunc import certFunc

class TestCerts(unittest.TestCase):

	def loadTestFile(self,fileName,binary=False):
		file=open(fileName,'rb' if binary else 'r')
		fileData=file.read()
		file.close()
		return(fileData)

	@classmethod
	def setUpClass(cls):
		cls.validPassword='testing123'
		cls.validX509=cls.loadTestFile(cls,'tests/www-cert.pem')
		cls.validPfx=cls.loadTestFile(cls,'tests/www.p12',True)
		cls.validBase64Pfx=cls.loadTestFile(cls,'tests/www-p12-base64.pem')
		cls.validRsaNoPwd=cls.loadTestFile(cls,'tests/www-key-nopwd.pem')
		cls.validRsaPwd=cls.loadTestFile(cls,'tests/www-key-pwd.pem')
		

	def testValidX509(self):
		self.assertTrue(certFunc.validateX509(self.validX509),"Should be valid cert")
	
	def testInvalidX509(self):
		self.assertFalse(certFunc.validateX509("invalid"),"Should be invalid cert")
	
	def testValidRsaPwdSkipPassword(self):
		self.assertFalse(certFunc.validateRsa(self.validRsaPwd),"Should fail. Encrypted key, no password given")

	def testValidRsaPwdBadPassword(self):
		self.assertFalse(certFunc.validateRsa(self.validRsaPwd,"invalid"),"Should fail. Encrypted key, invalid password given")

	def testValidRsaPwdGoodPassword(self):
		self.assertTrue(certFunc.validateRsa(self.validRsaPwd,self.validPassword),"Should succeed. Encrypted key, valid password")

	def testValidRsaNoPwdBadPassword(self):
		self.assertFalse(certFunc.validateRsa(self.validRsaNoPwd,self.validPassword),"Should fail. Unecrypted key, but password given")

	def testValidRsaNoPwd(self):
		self.assertTrue(certFunc.validateRsa(self.validRsaNoPwd),"Should succeed. Unencrypted key, no password given")
	
	def testInvalidRsa(self):
		self.assertFalse(certFunc.validateRsa("invalid"),"Should fail. Invalid key")

	def testInvalidPfx(self):
		self.assertFalse(certFunc.validatePfx("invalid",''),"Should fail. Invalid PFX")
	
	def testValidPfxBadPassword(self):
		self.assertFalse(certFunc.validatePfx(self.validPfx,"invalid"),"Should fail. Valid PFX, invalid password given")
	
	def testValidPfxGoodPassword(self):
		self.assertTrue(certFunc.validatePfx(self.validPfx,self.validPassword),"Should succeed. Valid PFX, valid password")

	def testValidBase64PfxGoodPassword(self):
		self.assertTrue(certFunc.validateBase64Pfx(self.validBase64Pfx,self.validPassword),"Should Succeed. Valid Base64 PFX, valid password")

	def testInValidBase64Pfx(self):
		self.assertFalse(certFunc.validateBase64Pfx("invalid","invalid"),"Should Succeed. Valid Base64 PFX, valid password")
	
	def testCorrectGetKeySize(self):
		self.assertEqual(certFunc.getRsaKeySize(self.validRsaNoPwd),2048,"Should Succeed. Correct key size")

	def testIncorrectGetKeySize(self):
		self.assertNotEqual(certFunc.getRsaKeySize(self.validRsaNoPwd),1024,"Should Succeed. Correct key size")
