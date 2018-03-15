import os
import base64
import json
import magic
from base64 import b64encode, b64decode
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

#Generate an IV of a given size
def generateIV():
  IV = os.urandom(magic.IV_SIZE)
  return IV
  
#Generate an IV, encrypt the message using key and IV in AES-CBC
def Myencrypt(message, key):
  #Checks key for the approriate size
  if (len(key) != magic.KEY_SIZE):
    print("The key has to be 32 bytes")
    return
  
  #Generates the IV
  IV = generateIV()
  
  #Initialize the padder to pad the ciphertext
  padder = padding.PKCS7(magic.PADDING_SIZE).padder()
  padded_data = padder.update(message) + padder.finalize()
  backend = default_backend()
  
  #Combines the AES algorithm with a mode CBC
  cipher = Cipher(algorithms.AES(key), modes.CBC(IV), backend = backend)
  
  #Initialize the encryptor instance
  encryptor = cipher.encryptor()
  
  #Encrypts the padded plaintext
  ct = encryptor.update(padded_data) + encryptor.finalize()
  
  print("Message has been encrypted")
  return ct, IV

#Inverse of Myencrypt function
#ct: Cipher text
#iv: Initialization Vector
#Decrypts the encrypted message created by the previous method
def Mydecrypt(ct, key, iv):
  
  #Combines the AES algorithm with a mode CBC
  decipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend = default_backend())
  
  #Instantiates the decryptor
  decryptor = decipher.decryptor()
  
  #Deciphers the encrypted message
  pt = decryptor.update(ct) + decryptor.finalize()
  
  #Get rid of the padding
  unpadder = padding.PKCS7(magic.PADDING_SIZE).unpadder()
  pt = unpadder.update(pt) + unpadder.finalize()
  print("The message has been decrypted")
  return pt

#Encrypting a file
def MyfileEncrypt(filepath):
  #Generating a key of a given length
  key = os.urandom(magic.KEY_SIZE)
  
  #Encrypted file name
  output = filepath + magic.ENC_EXT
  
  #read file in binary
  file = open(filepath, 'rb')
  bdata = file.read()
  bdata = b64encode(bdata)
  file.close()
  
  #Using the encryption method, encrypt the data in the image
  ct, iv = Myencrypt(bdata, key)
  
  #Creating the encrypted file
  encFile = open(output, "wb")
  encFile.write(ct)
  encFile.close()
  return ct, iv, key, magic.ENC_EXT

#Decrypting the file. Inverse of MyfileEncrypt
#This method does not use the Json method to decrypt the file
def MyfileDecrypt(filepath, key, iv):
  #Read the file and place its content in a variable
  file = open(filepath, 'rb')
  bdata = file.read()
  file.close()
  
  #Decrypt the encrypted data
  data = Mydecrypt(bdata, key, iv)
  data = b64decode(data)
  
  #Create a file to hold the decrypted data
  #Use for comparison with the original image
  decrypt = open("Decrypted.JPG", "wb")
  decrypt.write(data)
  decrypt.close()

#Writing to Json file
def WriteJson(ct, key, iv, ext):
  #Creates a json file
  output = open(magic.JSON_FILENAME, 'w')
  
  #Storing the Ciphertext, Key, IV, and Extension in a json file
  data = {"Cipher text": b64encode(ct).decode('utf-8') , "Key": b64encode(key).decode('utf-8'), "IV": b64encode(iv).decode('utf-8'), "Extension": ext}
  json.dump(data, output)
  output.close()

#Decryption with the json file 
#Correct Way
def MyfileDecrypt2(filepath, jsonPath):
  #Open the Json file for access
  jsonFile = open(jsonPath)
  
  #load the file's content onto variables
  EncryptData = json.load(jsonFile)
  ct = b64decode(EncryptData["Cipher text"])
  key = b64decode(EncryptData["Key"])
  iv = b64decode(EncryptData["IV"])
  ext = EncryptData["Extension"]
  
  #pt: plaintext
  #Decrypts the Ciphertext
  pt = Mydecrypt(ct, key, iv)
  
  #Change the data to its approriate format
  pt = b64decode(pt)
  #Create a file to hold the decrypted data
  #Use for comparison with the original image
  decrypt = open("Decrypted.JPG", "wb")
  decrypt.write(pt)
  decrypt.close()

#Testing Purposes
#Generating a key
key = os.urandom(magic.KEY_SIZE)
#Set message to test function
message = b"hello"
ct, iv = Myencrypt(message, key)
print("Original Message: ", message)
print("Cipher text: ", ct)
print("Decrypted Message: ", Mydecrypt(ct, key, iv))

ct, iv, key, extension = MyfileEncrypt(magic.PIC_PATH)
WriteJson(ct, key, iv, extension)
MyfileDecrypt2(magic.PIC_PATH + magic.ENC_EXT, magic.JSON_FILENAME)