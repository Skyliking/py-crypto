# -*- coding: utf-8 -*-
"""
Created on Mon Jun 21 19:52:31 2021

@author: JZN3SZH
"""
##################################################################################################
# This is the python programming practice to solve the homework problem
# in Coursera lesson Cryptography I (Week 3): Hash of Video File (SHA256)
# Author: JIN Zhecheng
##################################################################################################

# Reference Sites: https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/#
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

##################################################################################################
# Calcute data hash value by using SHA256
##################################################################################################
def CalBlkHash(data):
    digest = hashes.Hash(hashes.SHA256(), default_backend())
    digest.update(data)
    return (digest.finalize())

##################################################################################################
# Main function
##################################################################################################
def main():
    VideoFileList = os.listdir(os.getcwd())
    for VideoFileName in VideoFileList:
        if VideoFileName.lower().endswith('.mp4'):   # convert to lower cases and seach for mp4 files
            # Open video file and truncate it to 1KB blocks
            VideoFile = open(VideoFileName, mode='rb')
            FileSize = os.path.getsize(os.getcwd()+'\\'+VideoFileName)
            BlockNum = FileSize // 1024 + 1
            LastBlockSize = FileSize % 1024 # Size of last block could be shorter than 1KB
            
            # Calculate hash value of current block concatenated with the hash value of latter block   
            Hash_j = b''
            for index in range(BlockNum):
                VideoFile.seek(-(index*1024+LastBlockSize),2)
                DataBlock = VideoFile.read(1024)
                Hash_i = CalBlkHash(DataBlock+Hash_j)  
                Hash_j = Hash_i
            
            print ('The Hash value of 1st block of file "%s" is: ' %(VideoFileName))
            #print (BlockNum, LastBlockSize)
            #print (DataBlock, len(DataBlock))
            print (Hash_i.hex())
            
            VideoFile.close()

main()
