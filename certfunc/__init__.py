#!/usr/bin/env python3
import base64
from cryptography import x509
from cryptography.hazmat.primitives import serialization,hashes
from cryptography.hazmat.primitives.serialization.pkcs12 import serialize_key_and_certificates,load_key_and_certificates
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa


class certFunc():
	@staticmethod
	def validateX509(pemData):
		try:
			x509.load_pem_x509_certificate(pemData.encode())
			return(True)
		except:
			return(False)
	
	@staticmethod
	def validateRsa(pemData,password=None):
		try:
			if password:
				serialization.load_pem_private_key(pemData.encode(),password=password.encode())
			else:
				serialization.load_pem_private_key(pemData.encode(),password=None)
			return(True)
		except:
			return(False)

	@staticmethod
	def getRsaKeySize(pemData,password=None):
		if certFunc.validateRsa(pemData,password):
			if password:
				key=serialization.load_pem_private_key(pemData.encode(),password=password.encode())
			else:
				key=serialization.load_pem_private_key(pemData.encode(),password=None)
			return(key.key_size)
		else:
			return(0)

	@staticmethod
	def validatePfx(pfxData,password):
		try:
			load_key_and_certificates(pfxData,password.encode())
			return(True)
		except:
			return(False)

	@staticmethod
	def validateBase64Pfx(pemData,password):
		try:
			return(certFunc.validatePfx(base64.b64decode(pemData),password))
		except:
			return(False)
