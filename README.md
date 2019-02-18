Andrew Williams
andrewwi@uw.edu

This zip file contains:

1) 3Des.py: This file contains the implementation of 3Des as described in the assignment instructions.
2) 3DesDemo.py: This file is a demo script that uses os.system() to call 3Des.py from the command line.
3) input.txt: A text file used as sample input. This program should work with any text file.
4) readme.txt: This readme file.

This project was built and tested using Python 3.6.2. When testing on systems with both Python 2 and Python 3, I used a 
virtual environment, created by this or something similar:

python3 -m venv homework1
source homework1/bin/activate

3DesDemo.py does not take in any command line arguments. During processing, it prompts for a password and file input.

3Des.py takes in command line arguments as described in the assignment, for example:

3Des.py keygen password keyfile
3Des.py encrypt input keyfile output mode
3Des.py decrypt input keyfile output mode

Mode should be in all caps, for example, "ECB", "CBC", or "OFB".

For CBC and OFB modes, during encryption, the initialization vector is prepended to the ciphertext in the output file.

