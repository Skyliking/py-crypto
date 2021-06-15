##################################################################################################
# This is the python programming practice to solve the homework problem
# in Coursera lesson Cryptography I (Week 1): Stream Cipher Decryption
# Author: JIN Zhecheng
#
# Note:
# There are still some limitations of the decryption algorithm.
# The raw cracked target message text is as following:
#
#   "0he secuet message is: Wh0n using wsstreím cipher, never use the key more than once"
#
# Limitation 1:
#   Some character could not be cracked(shown as default value '0'), as no Space in same position
#   in other cipher texts.
#
# Limitation 2:
#   The algorithm could not distinguish Space and other special character (e.g.: '`','('), which could
#   lead to the similar XOR result (A-Za-z). Thus some characters are wrongly cracked
#   (e.g.: "secuet" instead of "secret", "wsstreím" instead of "a stream").
# 
#   Some wrong characters could be corrected with checking other cracked results in same position
#   of other XOR characters. For example, there are 2 cracked results ('a', 'w') for first character
#   in word "wsstreím". Howerver, wrong result 'w' is cracked in last group and it replaces
#   the correct result 'a'. Same method could be applied for correction 'í' in "wsstreím".
#   However this correction algorithm has not been implemented fully in code. Variable "WrongResultIndex" 
#   could be used to print other results, which provides a hint for manual correction.
#  
#   Another similar case is 'u' in "secuet". No correct cracked result could be provided by
#   previously mentioned hint. However it could be easily corrected manually.
#
# Limitation 3:  
#   The most special case is the first 's' in "wsstreím" (the correct character shall be a Space),
#   because in this message position the number of Space (7) is larger than the number of
#   character (4). Since this decryption algorithm is based on an assumption, that number of
#   character [A-Za-z] in same position of messages is larger than that number of space. No hint
#   could be provided by previous method as well.  
#
##################################################################################################
import re
#import numpy as np
#import os

# Function Switch
Method_Update = True

# Initialization
CipherTexts = []
MsgTextsXOR = []
EncryptTargetMsgText = []
ChrNum_a = []
ChrNum_b = []

SafeThreshold = 11 # Change this threshold to check the output differences
WrongResultIndex = 35 # [7/34/35/40]

##################################################################################################
# Read CipherText from the file, which is copied from Coursera web page
##################################################################################################
def ReadCipherTextFromFile():
    CipherTextFile = open("CipherTextFile.txt")
    # Read first line
    CipherTextLine = CipherTextFile.readline()
    # Start search CipherText with pattern "ciphertext #<Number>:"
    while CipherTextLine:
        searchObj = re.search(r'ciphertext #(\d|\d{2}):', CipherTextLine)
        if searchObj:
            # Skip next line as it is empty
            CipherTextFile.readline()
            # Store next line without space into the list
            CipherTexts.append(CipherTextFile.readline().strip())
            #print (searchObj.group(1))    
        # Read next line        
        CipherTextLine = CipherTextFile.readline()
        searchObj = re.search(r'target ciphertext \(decrypt this one\):',CipherTextLine)
        if searchObj:
            # Skip next line as it is empty
            CipherTextFile.readline()
            # Store next line without space into the list
            CipherTexts.append(CipherTextFile.readline().strip())
            # Read next line 
            CipherTextLine = CipherTextFile.readline()
    CipherTextFile.close()    
    #CipherText_TotalNum = len(CipherText)
    #print(CipherText_TotalNum)
    #print(CipherText[CipherText_TotalNum-1])

##################################################################################################
# XOR two Hex character to Hex value
##################################################################################################
def ChrXOR2Hex(a, b):
    return hex(int(a,16) ^ int(b,16))

##################################################################################################
# XOR two Hex character
################################################################################################## 
def ChrXOR(a, b):
    return chr(int(a,16) ^ int(b,16))

##################################################################################################
# XOR two Hex strings of different lengths
##################################################################################################    
def HexStrXOR(a, b):
    if len(a) > len(b):
       return "".join([ChrXOR2Hex(x, y).replace('0x','') for (x, y) in zip(a[:len(b)], b)])
    else:
       return "".join([ChrXOR2Hex(x, y).replace('0x','') for (x, y) in zip(a, b[:len(a)])])

##################################################################################################
# XOR all pairs of messages in message list
##################################################################################################   
def XORAllMsgs(MsgList):
    # define a two dimensional array
    l_MsgTextsXOR = [[0 for i in range(len(MsgList))] for i in range(len(MsgList))]
    for a in range(len(MsgList)):
        for b in range(len(MsgList)):
            l_MsgTextsXOR[a][b] = HexStrXOR(MsgList[a], MsgList[b])
    #print(len(MsgTextsXOR))
    #print(MsgTextsXOR[0][1])
    #print(HexStrXOR(CipherTexts[9],CipherTexts[10]))
    return l_MsgTextsXOR

##################################################################################################
# Check Msg[index~index+1] is an upper or lower character or not
##################################################################################################   
def isUpperOrLowerChr(Msg, index):
    return chr(int(Msg[index] + Msg[index+1],16)).isupper() or chr(int(Msg[index] + Msg[index+1],16)).islower()

##################################################################################################
# Count upper and lower character number with certain message index and position
##################################################################################################   
def CountChrNum(MsgTexts,MsgTextsLen,MsgIndex,ChrIndex):
    ChrNum = 0
    for x in range(MsgTextsLen):
        if isUpperOrLowerChr(MsgTexts[MsgIndex][x],ChrIndex):
            ChrNum += 1
    return ChrNum            

##################################################################################################
# Decrypt cipher texts based on below weak point:
#   Space XOR A-Z = A-Z
#   Space XOR a-z = A-Z
##################################################################################################   
def DecryptCipherTexts(CipherTextList):
    # XOR all pairs of cipher texts to get the XORed Message Texts
    MsgTextsXOR = XORAllMsgs(CipherTextList)
    MsgNum = len(CipherTextList)
    TargetMsgText = [0 for i in range(len(CipherTextList[MsgNum-1])//2)]
    #print (len(TargetMsgText))
    for a in range(MsgNum):
        for b in range(a+1, MsgNum):
            i = 0
            Debug_XORMsg = MsgTextsXOR[a][b]
            # check each character in XORed Msg
            while i < (len(CipherTextList[MsgNum-1])-1):
                # find an upper character
                XORChr_a_b = MsgTextsXOR[a][b][i] + MsgTextsXOR[a][b][i+1]
                if chr(int(XORChr_a_b,16)).isupper():
                    # New updated algorithm
                    if Method_Update:
                        # Count the character number with index a and b
                        ChrNum_a = CountChrNum(MsgTextsXOR,MsgNum,a,i)
                        ChrNum_b = CountChrNum(MsgTextsXOR,MsgNum,b,i)
                        # Set a threshold for sum of 2 counters
                        if (ChrNum_a + ChrNum_b) >= SafeThreshold:
                            
                            if ChrNum_a > ChrNum_b:
                                # Msg[a][i~i+1] is Space
                                if (int(MsgTextsXOR[a][MsgNum-1][i] + MsgTextsXOR[a][MsgNum-1][i+1],16) == 0):
                                    # in case Msg[t][i~i+1] is Space as well
                                    TargetMsgText[i//2] = ' '
                                else:
                                    # Get Msg[target][i~i+1] info from XORMsg[a][target][i~i+1] with XORing a Space
                                    TargetMsgText[i//2] = ChrXOR(MsgTextsXOR[a][MsgNum-1][i] + MsgTextsXOR[a][MsgNum-1][i+1], '20')
                                Debug_TargetMsgChr = TargetMsgText[i//2]
                                
                            elif b < (MsgNum-1):
                                # Msg[b][i~i+1] is Space
                                if (int(MsgTextsXOR[b][MsgNum-1][i] + MsgTextsXOR[b][MsgNum-1][i+1],16) == 0):
                                    # in case Msg[t][i~i+1] is Space as well
                                    TargetMsgText[i//2] = ' '
                                else:
                                    # Get Msg[target][i~i+1] info from XORMsg[b][target][i~i+1] with XORing a Space
                                    TargetMsgText[i//2] = ChrXOR(MsgTextsXOR[b][MsgNum-1][i] + MsgTextsXOR[b][MsgNum-1][i+1], '20')
                                Debug_TargetMsgChr = TargetMsgText[i//2]
                                
                            else:
                                # Msg[b][i~i+1] is Space, and Msg[b] is the target the message
                                TargetMsgText[i//2] = ' '
                                Debug_TargetMsgChr = TargetMsgText[i//2]
                            
                            # For wrong cracked character, print all other results
                            if i//2 == WrongResultIndex:
                                print (a,b,i,ChrNum_a,ChrNum_b,Debug_TargetMsgChr)
                    
                    # This algorithm has some problems, reserve for comparision
                    else:
                        # Msg[b] is not Msg[target]
                        if (b+1) < MsgNum:
                            Debug_XORChr_a_10 = MsgTextsXOR[a][MsgNum-1][i] + MsgTextsXOR[a][MsgNum-1][i+1]
                            if chr(int(MsgTextsXOR[a][MsgNum-1][i] + MsgTextsXOR[a][MsgNum-1][i+1],16)).isupper():
                                # Msg[a][i~i+1] is Space, get Msg[target][i~i+1] info from XORMsg[a][target][i~i+1] 
                                TargetMsgText[i//2] = chr(int(MsgTextsXOR[a][MsgNum-1][i] + MsgTextsXOR[a][MsgNum-1][i+1],16))
                                Debug_TargetMsgChr = TargetMsgText[i//2]
                            else:
                                # Msg[b][i~i+1] is Space, get Msg[target][i~i+1] info from XORMsg[b][target][i~i+1]
                                TargetMsgText[i//2] = chr(int(MsgTextsXOR[b][MsgNum-1][i] + MsgTextsXOR[b][MsgNum-1][i+1],16))                            
                                Debug_TargetMsgChr = TargetMsgText[i//2]
                        # Msg[b] is Msg[target] and a is not 0
                        elif a != 0:
                            Debug_XORChr_a_0 = MsgTextsXOR[a][0][i] + MsgTextsXOR[a][0][i+1]
                            if chr(int(MsgTextsXOR[a][0][i] + MsgTextsXOR[a][0][i+1],16)).isupper():
                                # Msg[a][i~i+1] is Space, get Msg[target][i~i+1] info from XORMsg[a][target][i~i+1] 
                                TargetMsgText[i//2] = chr(int(MsgTextsXOR[a][MsgNum-1][i] + MsgTextsXOR[a][MsgNum-1][i+1],16))
                                Debug_TargetMsgChr = TargetMsgText[i//2]
                            else:
                                # Msg[b/target][i~i+1] is Space
                                TargetMsgText[i//2] = ' '
                                Debug_TargetMsgChr = TargetMsgText[i//2]
                        # Msg[b] is Msg[target] and a is 0
                        else:
                            Debug_XORChr_a_9 = MsgTextsXOR[a][MsgNum-2][i] + MsgTextsXOR[a][MsgNum-2][i+1]
                            if chr(int(MsgTextsXOR[a][MsgNum-2][i] + MsgTextsXOR[a][MsgNum-2][i+1],16)).isupper():
                                # Msg[a][i~i+1] is Space, get Msg[target][i~i+1] info from XORMsg[a][target][i~i+1] 
                                TargetMsgText[i//2] = chr(int(MsgTextsXOR[a][MsgNum-1][i] + MsgTextsXOR[a][MsgNum-1][i+1],16))
                                Debug_TargetMsgChr = TargetMsgText[i//2]
                            else:
                                # Msg[b/target][i~i+1] is Space
                                TargetMsgText[i//2] = ' '
                                Debug_TargetMsgChr = TargetMsgText[i//2]
                i += 2
    return (TargetMsgText)

##################################################################################################
# Main function
##################################################################################################
def main():
    ReadCipherTextFromFile()
    #CipherTexts = [input('Please copy CipherText:') for index in range(CipherText_TotalNum)]

    EncryptTargetMsgText = DecryptCipherTexts(CipherTexts)

    for i in EncryptTargetMsgText: print(i, end="")
    print ('\n')

main()
