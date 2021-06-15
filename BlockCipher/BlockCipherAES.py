# -*- coding: utf-8 -*-
"""
Created on Tue Jun 15 10:28:40 2021

@author: JZN3SZH
"""
##################################################################################################
# This is the python programming practice to solve the homework problem
# in Coursera lesson Cryptography I (Week 2): Block Cipher (AES - CBC/CTR Mode)
# Author: JIN Zhecheng
##################################################################################################

# Reference Sites: https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/#
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

# Constants
AESModeCBC = 1
AESModeCTR = 2
BlockSize = 16

# Initialization
CBCKeys = []
CTRKeys = []
CBCCipherTexts = []
CTRCipherTexts = []

##################################################################################################
# Read key and cipher text from the file, which is copied from Coursera web page
##################################################################################################
def ReadKeyAndCipherTextFromFile():
    QuestionTextFile = open("QuestionText.txt")
    # Read first line
    QuestionTextLine = QuestionTextFile.readline()
    # Start search CBC/CTR Keys and CipherText with related pattern
    while QuestionTextLine:
        # Search CBC Keys:
        PatternIndex = QuestionTextLine.rfind('CBC key:')
        PatternIndexOffset = len('CBC key:')
        if PatternIndex >= 0:
            CBCKeys.append(QuestionTextLine[PatternIndex+PatternIndexOffset:].strip())

        # Search CTR Keys:
        PatternIndex = QuestionTextLine.rfind('CTR key:')
        PatternIndexOffset = len('CTR key:')
        if PatternIndex >= 0:
            CTRKeys.append(QuestionTextLine[PatternIndex+PatternIndexOffset:].strip())

        # Search CBC Cipher Texts:
        PatternIndex = QuestionTextLine.rfind('CBC Ciphertext')
        PatternIndexOffset = len('CBC Ciphertext 1:')
        if PatternIndex >= 0:
            CBCCipherTexts.append(QuestionTextLine[PatternIndex+PatternIndexOffset:].strip())
        
        # Search CTR Cipher Texts:
        PatternIndex = QuestionTextLine.rfind('CTR Ciphertext')
        PatternIndexOffset = len('CTR Ciphertext 1:')
        if PatternIndex >= 0:
            CTRCipherTexts.append(QuestionTextLine[PatternIndex+PatternIndexOffset:].strip())

        # Read next line        
        QuestionTextLine = QuestionTextFile.readline()

    QuestionTextFile.close()    

    # print(len(CBCKeys))
    # print(CBCKeys[0])
    # print(CTRKeys[1])
    # print(CBCCipherTexts[1])
    # print(CTRCipherTexts[1])

##################################################################################################
# Decrypt Block Cipher using AES (CBC / CTR mode)
##################################################################################################
def DecryptBlockCipher_AES(AESMode, AESKey, AESCipherText):
    if AESMode == AESModeCBC:
        # iv length must be the same length as Blocksize
        iv = AESCipherText[:BlockSize]
        cipher = Cipher(algorithms.AES(AESKey), modes.CBC(iv), default_backend())
        decryptor = cipher.decryptor()
        # Data shall be unpadded in CBC mode
        unpadder = padding.PKCS7(BlockSize*8).unpadder()
        padded_data = (decryptor.update(AESCipherText) + decryptor.finalize())[BlockSize:]
        return (unpadder.update((padded_data)) + unpadder.finalize()).decode()
    elif AESMode == AESModeCTR:
        # nonce length must be the same length as Blocksize
        nonce = AESCipherText[:BlockSize]
        cipher = Cipher(algorithms.AES(AESKey), modes.CTR(nonce), default_backend())
        decryptor = cipher.decryptor()
        # nonce in CipherText shall be truncated
        return (decryptor.update(AESCipherText[BlockSize:]) + decryptor.finalize()).decode()
    else:
        raise Exception("Error: Invalid AES Mode:", AESMode)

##################################################################################################
# Main function
##################################################################################################
def main():
    ReadKeyAndCipherTextFromFile()

    for i in range(len(CBCKeys)):
        KeyBytes = bytes.fromhex(CBCKeys[i])
        CipherTextBytes = bytes.fromhex(CBCCipherTexts[i])
        EncryptPlainText = DecryptBlockCipher_AES(AESModeCBC, KeyBytes, CipherTextBytes)
        print('CBC Mode Plain Text ',i,':',EncryptPlainText)

    for i in range(len(CTRKeys)):
        KeyBytes = bytes.fromhex(CTRKeys[i])
        CipherTextBytes = bytes.fromhex(CTRCipherTexts[i])
        EncryptPlainText = DecryptBlockCipher_AES(AESModeCTR, KeyBytes, CipherTextBytes)
        print('CTR Mode Plain Text ',i,':',EncryptPlainText)

main()
