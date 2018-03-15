import os
import base64
import json
from base64 import b64encode, b64decode
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

def generateIV():
  IV = os.urandom(16)
  return IV
  
def Myencrypt(message, key):
  if (len(key) != 32):
    print("The key has to be 32 bytes")
    return
  
  #iv
  IV = generateIV()
  
  padder = padding.PKCS7(128).padder()
  padded_data = padder.update(message) + padder.finalize()
  backend = default_backend()
  
  cipher = Cipher(algorithms.AES(key), modes.CBC(IV), backend = backend)
  encryptor = cipher.encryptor()
  ct = encryptor.update(padded_data) + encryptor.finalize()
  return ct, IV

def Mydecrypt(ct, key, iv):
  pt = Cipher(algorithms.AES(key), modes.CBC(iv), backend = default_backend())
  decryptor = pt.decryptor()
  data = decryptor.update(ct) + decryptor.finalize()
  unpadder = padding.PKCS7(128).unpadder()
  data = unpadder.update(data) + unpadder.finalize()
  return data
  
def MyfileEncrypt(filepath):
  key = os.urandom(32)
  
  output = filepath + ".encrypt"
  #read file in binary
  file = open(filepath, 'rb')
  bdata = file.read()
  bdata = b64encode(bdata)
  file.close()
  
  ct, iv = Myencrypt(bdata, key)
  
  encFile = open(output, "wb")
  encFile.write(ct)
  encFile.close()
  return ct, iv, key, '.encrypt'
  
def MyfileDecrypt(filepath, key, iv):
  file = open(filepath, 'rb')
  bdata = file.read()
  file.close()
  
  filepath.replace(extension, '')
  data = Mydecrypt(bdata, key, iv)
  data = b64decode(data)
  decrypt = open("Hello.JPG", "wb")
  decrypt.write(data)
  decrypt.close()

#Writing to Json file
def WriteJson(ct, key, iv, ext):
  output = open("EncryptInfo.json", 'w')
  data = {"Cipher text": b64encode(ct).decode('utf-8') , "Key": b64encode(key).decode('utf-8'), "IV": b64encode(iv).decode('utf-8'), "Extension": ext}
  json.dump(data, output)
  output.close()

#Decryption with the json file  
def MyfileDecrypt2(filepath, jsonPath):
  with open(jsonPath) as jsonFile:
    EncryptData = json.load(jsonFile)
    ct = b64decode(EncryptData["Cipher text"])
    key = b64decode(EncryptData["Key"])
    iv = b64decode(EncryptData["IV"])
    ext = EncryptData["Extension"]
  pt = Mydecrypt(ct, key, iv)
  pt = b64decode(pt)
  decrypt = open("Hello.JPG", "wb")
  decrypt.write(pt)
  decrypt.close()
  
key = os.urandom(32)
message = b"hello"
ct, iv = Myencrypt(message, key)
print(ct)
print(Mydecrypt(ct, key, iv))

ct, iv, key, extension = MyfileEncrypt("Capture.JPG")
WriteJson(ct, key, iv, extension)
MyfileDecrypt2("Capture.JPG.encrypt", "EncryptInfo.json")