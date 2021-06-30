# -*- coding: utf-8 -*-
"""
Created on Mon Jun 28 09:58:00 2021

@author: JZN3SZH
"""
##################################################################################################
# This is the python programming practice to solve the homework problem
# in Coursera lesson Cryptography I (Week 4): Authenticated Encryption - Padding Oracle Attack
# Author: JIN Zhecheng
##################################################################################################

import urllib3
import sys

TARGET = 'http://crypto-class.appspot.com/po?er='
CT = b'f20bdba6ff29eed7b046d1df9fb7000058b1ffb4210a580f748b4ac714c001bd4a61044426fb515dad3f21f18aa577c0bdf302936266926ff37dbf7035d5eeb4'
BlockSize = 16

#--------------------------------------------------------------
# padding oracle
#--------------------------------------------------------------
class PaddingOracle(object):
    def query(self, q):
        url = TARGET + q                 # Create query URL
        url = 'http://crypto-class.appspot.com/po?er=f20bdba6ff29eed7b046d1df9fb7000058b1ffb4210a580f748b4ac714c001bd4a61044426fb515dad3f21f18aa577c0bdf302936266926ff37dbf7035d5eeb4'
        http = urllib3.PoolManager()
        try:
            req = http.request('GET', url, retries = False)         # Send HTTP request to server
        except urllib3.exceptions.HTTPError:
            print ("We got: %d" % req.status)       # Print response code
            if req.status == 404:
                return True # good padding
            return False # bad padding
        else:
            return True

if __name__ == "__main__":
    
    po = PaddingOracle()
    
    BlockNum = len(CT)//2//BlockSize
    CipherText = []
    PlainText = []
    for i in range(0,len(CT),2):
        CipherText.append(int(CT[i:i+2],16))
        PlainText.append(0)
        
    for Block_i in range (BlockNum - 1):
        for Byte_j in range((BlockSize-1),-1,-1):
            # Create an empty tampered CipherText, block numbers shall be 2,3,4
            CipherText_T_Size = BlockSize * (Block_i+2)
            CipherText_T = [0 for i in range(CipherText_T_Size)]
            # Padding Value is 0x01 - 0x10
            PadVal = BlockSize - Byte_j
            # Guess value from 0 - 255
            g = 0
            PadValCheck = False
            while (g<256) and (not PadValCheck):
                PlainText[Block_i*BlockSize+Byte_j] = g
                for i in range(BlockSize*Block_i+Byte_j):
                    CipherText_T[i] = CipherText[i]
                for i in range(BlockSize*(Block_i+1),BlockSize*(Block_i+2)):
                    CipherText_T[i] = CipherText[i]                    
                # print (CipherText)
                # print (CipherText_T)
                for i in range(BlockSize*Block_i+Byte_j,BlockSize*(Block_i+1)):
                    CipherText_T[i] = CipherText[i] ^ PlainText[i] ^ PadVal
                CT_T = ''.join([format(CipherText_T[i],'02x') for i in range(len(CipherText_T))])
                print (CT_T)
                PadValCheck = po.query(CT_T)       # Issue HTTP query with the given argument
                g += 1
                
            print (g)
            
            
