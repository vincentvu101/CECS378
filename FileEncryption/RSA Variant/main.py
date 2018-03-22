import os
import base64
import json
import magic
from base64 import b64encode, b64decode
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import asymmetric
from cryptography.hazmat.primitives import hashes

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
  print("The file has been encrypted")
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
  print("Generating JSON File with the necessary contents")

#Decryption with the json file 
#Correct Way
def MyfileDecrypt2(filepath, jsonPath):
  #Open the Json file for access
  jsonFile = open(jsonPath, 'r')
  
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
  print("The decrypted data is stored in Decrypted.JPG")
  decrypt.write(pt)
  decrypt.close()

#------------------------------------------------------------------------------------------------------------
#------------------------------------------------------------------------------------------------------------
#TESTING
#Generate a Private Key
private_key = rsa.generate_private_key(
    public_exponent = 65537,
    key_size = 2048,
    backend = default_backend()
)

#private key serialization
private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
    )
private_pem.splitlines()[0]

#public key generation
public_key = private_key.public_key()

#public key serialization
public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
public_pem.splitlines()[0]

#write public key to pem file
file = open(magic.PUBLIC_KEY_PATH, 'wb')
file.write(public_pem)
file.close()

#write private key to pem file
file = open(magic.PRIVATE_KEY_PATH, 'wb')
file.write(private_pem)
file.close()

#Encrypting key using generated public key
def MyRSAEncrypt(filepath, RSA_Publickey_filepath):
  #Encrypt the file
  C, IV, key, ext = MyfileEncrypt(filepath)
  
  #Load the public key from file
  with open(RSA_Publickey_filepath, "rb") as key_encrypt:
    public_key = serialization.load_pem_public_key(
    key_encrypt.read(),
    backend=default_backend()
    )
  key_encrypt.close()
  
  #Use public key to encrypt the key in OAEP padding
  RSACipher = public_key.encrypt(
    key,
    asymmetric.padding.OAEP(
      mgf=asymmetric.padding.MGF1(algorithm=hashes.SHA256()),
      algorithm=hashes.SHA256(),
      label=None
      )
    )
  
  return RSACipher, C, IV, ext
  
def MyRSADecrypt(RSACipher, C, IV, ext, RSA_Privatekey_filepath):
  #Load the private key from file
  with open(RSA_Privatekey_filepath, "rb") as key_decrypt:
    private_key = serialization.load_pem_private_key(
    key_decrypt.read(),
    password=None,
    backend=default_backend()
    )
    
  #Use the private key to decrypt the RSACipher
  key = private_key.decrypt(
    RSACipher,
    asymmetric.padding.OAEP(
      mgf=asymmetric.padding.MGF1(algorithm=hashes.SHA256()),
      algorithm=hashes.SHA256(),
      label=None
      )
    )
  
  #Using the decrypted RSACipher as key, decrypt the ciphertext
  pt = Mydecrypt(C, key, IV)
  pt = b64decode(pt)
  
  #Create a file to hold the decrypted data
  #Use for comparison with the original image
  decrypt = open(magic.DECRYPTED_FILE_PATH, "wb")
  decrypt.write(pt)
  decrypt.close()
  
  return pt

#Testing MyRSAEncrypt and MyRSADecrypt
RSACipher, ct, iv, ext = MyRSAEncrypt(magic.PIC_PATH, magic.PUBLIC_KEY_PATH)
MyRSADecrypt(RSACipher, ct, iv, ext, magic.PRIVATE_KEY_PATH)
