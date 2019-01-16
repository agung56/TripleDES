#!/usr/bin/python3
import sys
import random
#for bit manipulation
from bitstring import BitArray
#for initial password hash
from Cryptodome.Hash import SHA256

#This class contains all the methods used for encrypting and decrypting with triple DES, 
#as well as the methods for generating the key file. Below this class is the code
#that actually takes in input from the command line and calls this class.
class des:
    
    #Various items stored as class variables. This may be an artifact of my early days
    #as a Java programmer, but in certain cases I preferred to use a class variable 
    #rather than pass lots of variables back and forth between methods. If this were 
    #"production", I feel like I would probably want to take more steps to obscure or hide the 
    #key when it's in memory, but for this, I decided not to worry about that part.
    def __init__(self):
        self.key = BitArray()
        self.roundKeys = list()
        self.setLookupTables()        
    
    #I set most of the lookup tables as class variables so that I only have to do it once, on 
    #instantiation of the class, and they're accessible across methods.
    def setLookupTables(self):
        #This is the initial permutation of the key
        self.INITIAL_P = [58, 50, 42, 34, 26, 18, 10, 2,
                          60, 52, 44, 36, 28, 20, 12, 4,
                          62, 54, 46, 38, 30, 22, 14, 6,
                          64, 56, 48, 40, 32, 24, 16, 8,
                          57, 49, 41, 33, 25, 17, 9, 1,
                          59, 51, 43, 35, 27, 19, 11, 3,
                          61, 53, 45, 37, 29, 21, 13, 5,
                          63, 55, 47, 39, 31, 23, 15, 7]
        
        #Permutation to be used to generate each 48-bit key
        self.ROUND_P = [14, 17, 11, 24, 1, 5, 3, 28,
                15, 6, 21, 10, 23, 19, 12, 4,
                26, 8, 16, 7, 27, 20, 13, 2,
                41, 52, 31, 37, 47, 55, 30, 40,
                51, 45, 33, 48, 44, 49, 39, 56,
                34, 53, 46, 42, 50, 36, 29, 32] 
        
        #Left shift to be applied to each of the sixteen round keys
        self.roundShift = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1]
        
        #The eight DES S-Boxes
        self.S_BOX = [         
                      [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
                       [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
                       [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
                       [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
                      ],

                    [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
                     [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
                     [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
                     [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
                    ],

                    [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
                     [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
                     [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
                     [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
                    ],

                    [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
                     [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
                     [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
                     [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
                    ],  

                    [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
                     [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
                     [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
                     [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
                    ], 

                    [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
                     [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
                     [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
                     [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
                    ], 

                    [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
                     [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
                     [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
                     [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
                    ],
   
                    [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
                     [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
                     [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
                     [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
                    ]
                   ]
        
        #Expansion permutation used to expand a 32-bit segment to 48 bits
        self.EXPANSION_P = [32, 1, 2, 3, 4, 5,
                            4, 5, 6, 7, 8, 9,
                            8, 9, 10, 11, 12, 13,
                            12, 13, 14, 15, 16, 17,
                            16, 17, 18, 19, 20, 21,
                            20, 21, 22, 23, 24, 25,
                            24, 25, 26, 27, 28, 29,
                            28, 29, 30, 31, 32, 1]
        
        #P-Box Permutation
        self.P_BOX = [16, 7, 20, 21, 29, 12, 28, 17,
                      1, 15, 23, 26, 5, 18, 31, 10,
                      2, 8, 24, 14, 32, 27, 3, 9,
                      19, 13, 30, 6, 22, 11, 4, 25]
        
        self.P_FINAL = [40, 8, 48, 16, 56, 24, 64, 32,
                        39, 7, 47, 15, 55, 23, 63, 31,
                        38, 6, 46, 14, 54, 22, 62, 30,
                        37, 5, 45, 13, 53, 21, 61, 29,
                        36, 4, 44, 12, 52, 20, 60, 28,
                        35, 3, 43, 11, 51, 19, 59, 27,
                        34, 2, 42, 10, 50, 18, 58, 26,
                        33, 1, 41, 9, 49, 17, 57, 25]        
    
    #Function to permute the bits of a starting array based on a given lookup table    
    def permuteBits(self, inputBits, table):
        permuted = BitArray()
        count = 0
        #Go through the lookup table in order
        for x in table:
            #And append the bit at the given location of the initial array
            permuted.append(inputBits[(x - 1):x])
            count = count + 1
        #At the end, you have an array of bits permuted as dictated by the lookup table
        return permuted               
    
    #Method to create the keyfile from an initial 192-bit key
    #The 192-bit key contains the 3 starting 64-bit keys in sequential order
    def createKeyFile(self, initialKey, filename):
        
        #Lookup table to be used in permuting the key from 64 to 56 bits
        #In "real" DES, the deleted bits are parity-checking bits, but this is 
        #just a demo/simulation.
        KEY_P = [57, 49, 41, 33, 25, 17, 9,
                 1, 58, 50, 42, 34, 26, 18,
                 10, 2, 59, 51, 43, 35, 27,
                 19, 11, 3, 60, 52, 44, 36,
                 63, 55, 47, 39, 31, 23, 15,
                 7, 62, 54, 46, 38, 30, 22,
                 14, 6, 61, 53, 45, 37, 29,
                 21, 13, 5, 28, 20, 12, 4]
        
        keyCount = 0
        keyWriter = open(filename, 'w')
        
        #Loop 3 times, each time taking the next 64-bit key and permuting it the 56-bit DES key
        while keyCount < 192:
            subKey = initialKey[keyCount:(keyCount + 64)]
            subKey = self.permuteBits(subKey, KEY_P)
            
            #After permuting, write 56-bit key to the keyfile
            #Written as a string of 1s and 0s rather than a literal bit sequence to aid in debugging
            keyWriter.write(subKey.bin)
            keyCount = keyCount + 64
            
        keyWriter.closed
    
    #Method to read in the keyfile, where the keyfile is a string of 168 0s and 1s                       
    def readKeyFile(self, filename):
        
        keyReader = open(filename, 'r')
        self.key = BitArray(bin=keyReader.read())
    
    #Method to generate 16 round keys, based on an initial 56-bit key
    def roundKeyGen(self, initialKey, operation):
                
        cKey = BitArray()
        dKey = BitArray()
        self.roundKeys = list()
        
        for roundCount in range(0,16):
        
            #Split 56-bit key into C and D
            cKey = initialKey[0:28]
            dKey = initialKey[28:56]
          
            #Rotate to the left by the amount appropriate for each round          
            cKey.rol(self.roundShift[roundCount])
            dKey.rol(self.roundShift[roundCount])
            
            #Put them back together for the 56-bit key    
            cKey.append(dKey)
            initialKey = cKey
            #The 48-bit permutation is calculated and stored in the list of round keys
            #The 56-bit key is kept and saved to calculate the next round key 
            self.roundKeys.append(self.permuteBits(initialKey, self.ROUND_P))
        
        #If we're doing a decryption we need to run the round keys in reverse order.
        if (operation == 'DECRYPT'):
        
            roundKeyReversal = list()
            i = 0
            
            for i in range(0,16):
                roundKeyReversal.append(self.roundKeys[15 - i])
                
            self.roundKeys = roundKeyReversal
                
    def encrypt(self, infile, outfile, mode):
        #If encryption, we run the triple DES algorithm with operation set to 'ENCRYPT'
        self.runTripleDes(infile, outfile, mode, 'ENCRYPT')
        
    def decrypt(self, infile, outfile, mode):
        #If decryption, we run the triple DES algorithm with operation set to 'DECRYPT'
        self.runTripleDes(infile, outfile, mode, 'DECRYPT')
    
    def runTripleDes(self, infile, outfile, mode, operation):
        
        inputRead = open(infile, 'r')
        stringToProcess = inputRead.read()
        #If reading from unencrypted text file, then file input will be a standard string
        #Otherwise it will be a hex string
        if (operation == 'ENCRYPT'):        
            inputBits = BitArray(bytes=stringToProcess.encode('utf8'))
            inputBits = self.bufferInput(inputBits)
        elif (operation == 'DECRYPT'):
            inputBits = BitArray(hex=stringToProcess)
            
            #If decrypting, you will need to use the last key (K3) and the first key (K1) third.
            #So just reverse the order of the 3 56-bit subkeys in the overall 168-bit key.
            #
            #This does not apply to OFB, which treats encryption and decryption the same.
            if (mode != 'OFB'):
                keyReverse = BitArray()
                j = 0
                for j in range(0,3):
                    readFrom = 112 - (j*56)
                    keyReverse.append(self.key[readFrom:(readFrom + 56)])
                self.key = keyReverse
            
        
        #position will track our progress through the input bits        
        position = 0
        #outputBits is where we're going to store the finished output and will 
        #eventually write it to the output file.
        outputBits = BitArray()
        
        #For CBC and OFB modes we need to set an initialization vector.
        if (mode != 'ECB'):
            
            #If encrypting, generate a new 64 bit random string.
            if (operation == 'ENCRYPT'):
                
                #xorVector will store the initialization vector here
                #During triple DES it will keep storing the value to use for XORing in the next round
                xorVector = BitArray()
                #Leaving the seed argument blank seeds rand with the time
                random.seed()
                randomNum = random.getrandbits(64)
                
                #Convert random integer to 64-bit bitstring
                xorVector = BitArray(uint = randomNum, length=64)
                #Append to the beginning of the output string, so IV will be the first 
                #64 bits of the file
                outputBits.append(xorVector)
                
            elif (operation == 'DECRYPT'):
                #If decrypting, the first 64 bits of the input is the IV. Read in, store, 
                #and delete it from the input.
                xorVector = inputBits[0:64]
                del inputBits[:64]         
                
        
        #This is the loop that actually cycles through each 64 bits of the input.            
        while position < inputBits.length:
            
            #unProcessedBits stores the next 64 bit input from the file. 
            #It's plaintext if encrypting, ciphertext if decrypting.
            unprocessedBits = inputBits[position:(position + 64)]
            
            #If CBC our input into the encryption will be the XOR Vector from the previous round 
            #(or IV if the first round) XORed with the plaintext from file
            if (mode == 'CBC'):
                if (operation == 'ENCRYPT'):
                    segmentInput = unprocessedBits ^ xorVector
                #For CBC decryption our input into the encryption is ciphertext
                else:
                    segmentInput = unprocessedBits                
            #In OFB mode (encryption or decryption) input is the result of the XOR from the previous round.        
            elif (mode == 'OFB'):
                segmentInput = xorVector
            #In ECB mode (encryption or decryption), our input just the plaintext (encryption) or ciphertext (decryption)  
            else:
                segmentInput = unprocessedBits
            
            #If OFB, decryption runs the same as encryption.                  
            if (mode == 'OFB'):
                processedBits = self.tripleDesSegment(segmentInput, 'ENCRYPT')
            #Else let the triple DES algorithm know if it's encrypting or decrypting
            else:
                #The triple DES segment method is what actually does the round key 
                #generation and processing for each 64 bit segment
                processedBits = self.tripleDesSegment(segmentInput, operation)
            
            #For OFB mode           
            if (mode == 'OFB'):
                #The output from this round of 3DES is stored as the XOR vector for the next round
                xorVector = processedBits
                #Final output of this cycle is an XOR of the 3DES output and the 
                #unprocessed file input (plaintext if encrypting, ciphertext if decrypting). 
                segmentOutput = unprocessedBits ^ processedBits
            #For CBC mode
            elif (mode == 'CBC'): 
                #On encryption, both final output (ciphertext) and XOR vector for next round are the 
                #output from this round of 3DES.
                if (operation == 'ENCRYPT'):
                    xorVector = processedBits
                    segmentOutput = processedBits   
                #For decryption, final output is an XOR of output from this round of 3DES
                #and ciphertext from previous round.
                if (operation == 'DECRYPT'):
                    segmentOutput = processedBits ^ xorVector
                    #For next round, store xorVector as ciphertext from this round 
                    xorVector = unprocessedBits
            #If ECB
            else:
                #Final output is the direct output from 3DES algorithm
                segmentOutput = processedBits
                
            #Append final output to string of output bits
            outputBits.append(segmentOutput)
            #Increment position for the next round of 3DES
            position = position + 64
        
        #After 3DES is done, write output
        outputWriter = open(outfile,'w')                
        
        #If the overall operation was an encrypt, we're writing out an encrypted hex string    
        if (operation == 'ENCRYPT'):
            outputWriter.write(outputBits.hex)
        #If the overall operation was a decrypt, we're writing out a cleartext string.    
        elif (operation == 'DECRYPT'):    
            #Remove the buffer that was originally added to make sure the input 
            #was divisible by 64 bits
            bitsToProcess = self.removeBuffer(outputBits)
            outputWriter.write((bitsToProcess.bytes).decode('utf8'))

    #Runs Triple DES on a given bit string, for the given operation and mode.    
    def tripleDesSegment(self, bitsToProcess, oper):
        
        i = 0
        #For Triple DES, repeat the DES process 3 times
        for i in range(0,3):
            #Grab the next 56-bit portion of the 168-bit key.
            stepKey = self.key[(56 * i):((56 * i) + 56)]
            #Generate the 16 48-bit round keys off the 56-bit key
            self.roundKeyGen(stepKey, oper)
            
            #Run DES on the input string. The keys are stored in class variables, and set 
            #in the appropriate order for encryption or decryption by the generator method.
            bitsToProcess = self.runSixteenRounds(bitsToProcess)
            
            #Flip between encryption and decryption on every round but the last
            if (i != 2):
                if (oper == 'ENCRYPT'):
                    oper = 'DECRYPT'
                elif (oper == 'DECRYPT'):
                    oper = 'ENCRYPT'
        
        return bitsToProcess
        
        
    #Method to buffer the input string so the number of bits to encrypt is
    #evenly divisible by 64    
    def bufferInput(self, inputBits):
        
        length = inputBits.length
        #Get the modulus of the input string length at 64
        amtToBuffer = length % 64
        #If length is not evenly divisible by 64, then the amount
        #we need to buffer is actually (64 - modulus)
        if (amtToBuffer > 0):
            amtToBuffer = 64 - amtToBuffer
        
        #Append the appropriate hex string based on the amount of buffer needed
        if (amtToBuffer == 8):
            inputBits.append('0x01')
        elif (amtToBuffer == 16):
            inputBits.append('0x0202')
        elif (amtToBuffer == 24):
            inputBits.append('0x030303')
        elif (amtToBuffer == 32):
            inputBits.append('0x04040404')
        elif (amtToBuffer == 40):
            inputBits.append('0x0505050505')
        elif (amtToBuffer == 48):
            inputBits.append('0x060606060606')
        elif (amtToBuffer == 56):
            inputBits.append('0x07070707070707')
        
        return inputBits
    
    #Method to remove hex buffer after decryption, if one is present
    def removeBuffer(self, inputBits):
        
        #Check the last byte. If it's part of a buffer, crop the necessary length
        #from the string
        testByte = inputBits[(inputBits.length - 8):inputBits.length]
        if(testByte=='0x07'):
            del inputBits[-56:]
        elif(testByte=='0x06'):
            del inputBits[-48:]
        elif(testByte=='0x05'):
            del inputBits[-40:]
        elif(testByte=='0x04'):
            del inputBits[-32:]
        elif(testByte=='0x03'):
            del inputBits[-24:]
        elif(testByte=='0x02'):
            del inputBits[-16:]
        elif(testByte=='0x01'):
            del inputBits[-8:]    
            
        return inputBits
      
    #Method to process the next 64-bit segment of plaintext    
    def runSixteenRounds(self, inputBits):
        
        #Do initial permutation on the plaintext
        inputBits = self.permuteBits(inputBits, self.INITIAL_P)
        
        #Split into L0 and R0
        leftBits = inputBits[0:32]
        rightBits = inputBits[32:64]
        
        #Do 16 rounds of encryption/decryption
        for roundCount in range(0,16):
            #Permute the 32 bits of R0 into 48
            expandedBits = self.permuteBits(rightBits, self.EXPANSION_P)
            
            #XOR the right bits and the round key
            result = expandedBits ^ self.roundKeys[roundCount]
        
            #Run the SBoxes on the result of the right bits/round key XOR
            result = self.sBoxes(result)
            #Do a PBox permutation
            result = self.permuteBits(result, self.P_BOX)
            #XOR the result with the left side
            result = result ^ leftBits
        
            #Swap the left and right if it's not the last round
            if (roundCount < 15):
                leftBits = rightBits            
                rightBits = result
            else:
                leftBits = result
            
        #After 16 rounds, concatenate left and right sides
        cText = leftBits
        cText.append(rightBits)
        
        #Do final permutation
        cText = self.permuteBits(cText, self.P_FINAL)
        
        return cText        
        
    #Method to run the S-Box substitutions for a single round        
    def sBoxes(self, inputString):
        
        outputString = BitArray()
        
        sBoxIncrement = 0
        #8 SBoxes
        for sBoxIncrement in range(0,8):
            #Take the next 6 characters of the input string
            currentPos = sBoxIncrement * 6
            currentBits = inputString[currentPos:(currentPos + 6)]
            #The four inner bits are the column lookup
            innerBits = currentBits[1:5]
            #The two outer bits are the row lookup
            outerBits = currentBits[0:1]
            outerBits.append(currentBits[5:6])
            #Find the correct substitution in the SBox and append the bit representation to the output string
            nextSegment = BitArray(uint=self.S_BOX[sBoxIncrement][outerBits.uint][innerBits.uint],length=4)
            outputString.append(nextSegment)
            
        return outputString 
                        
#Option 1: Key Generation
if sys.argv[1] == 'genkey':
    passwd = sys.argv[2]
    #Hash the password using SHA256
    hashObj = SHA256.new(passwd.encode("utf8"))
    filename = sys.argv[3]
    
    #For creating the keys, we will split the first 192 bits of the hash into 3 64-bit keys and discard the rest
    bitHash = BitArray(hashObj.digest())
    #Take a segment of the hash long enough to split into 3 64-bit keys
    #(64 rather than 56 because I included the initial key permutation to remove 
    #parity bits. I know they're not really parity bits in this case, but I didn't 
    #realize we didn't need to do this until after I'd already implemented it. I left it in, 
    #since it didn't seem to be hurting anything.)
    bitHash = bitHash[0:192]
    #print(bitHash.hex)
    
    desKeygen = des()
    #Create key file given an initial key hash
    desKeygen.createKeyFile(bitHash, filename)
    
#Option 2: 3DES Encryption
elif sys.argv[1] == 'encrypt':
    infile = sys.argv[2]
    keyfile = sys.argv[3]
    outfile = sys.argv[4]
    mode = sys.argv[5]
    
    encrypter = des()
    #Read in specified keyfile
    encrypter.readKeyFile(keyfile)
    #Run encryption
    encrypter.encrypt(infile, outfile, mode)  
    
    
#Option 3: 3DES Decryption
elif sys.argv[1] == 'decrypt':
    infile = sys.argv[2]
    keyfile = sys.argv[3]
    outfile = sys.argv[4]
    mode = sys.argv[5]
    
    decrypter = des()
    #Read in specified keyfile
    decrypter.readKeyFile(keyfile)
    #Run decryption
    decrypter.decrypt(infile, outfile, mode)  
    
else:
    print("Invalid command line arguments")
    
    
