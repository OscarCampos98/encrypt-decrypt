# encrypt-decrypt

# Assignment Context:
This project was completed as part of CPSC 418 (Introduction to Cryptography), where the goal was to create a custom encryption algorithm inspired by real-world cryptographic challenges. The assignment's hypothetical scenario involves a dissident in a repressive regime who needs to secure communications using a novel encryption algorithm. The assignment required the implementation of various cryptographic functions in Python, adhering to standards like FIPS 202 and NIST SP 800-185.


# Overview:
In this project, I developed a program to encrypt and decrypt files, drawing on the specifications provided in our assignment. The task was inspired by historical cryptographic challenges and the theoretical scenario of a dissident leveraging encryption for secure communication. Utilizing Python's cryptographic libraries and adhering to standards like FIPS 202 and NIST SP 800-185, a algorithm for data encryption, decryption, and brute-force password generation was created. Throughout the development, I consulted Python's official documentation, RFCs, and StackOverflow to navigate complex cryptographic issues. The code is thoroughly commented, highlighting the resources and logic behind each implemented function.

Files:
encrypt_decrypt.py: 
    The core script that integrates encryption, decryption, password generation, and cryptographic functions.
test_encrypt_decrypt.py:
     A test script that allows for the testing of core functions without executing the entire script, enabling efficient          verification of the encryption and decryption processes.

# Key Features Implemented:
generate_iv:
  Utilized the library secrets, function token_bytes, to generate a pseudo-random number.
  Resource: Python Docs - secrets module

xor:
  Checks that both Bytes are of equal length. If not, it checks which Byte is smallest and pads the end of the                 bytearray with the corresponding number of 0's.
  Resource: Stack Overflow - Fast XORing bytes in Python

left_encode:
  This functions implement various encoding schemes as per NIST Special Publication 800-185, preparing data for                hashing or encryption.

pseudoCSHAKE256:
  Custom implementation of the cSHAKE256 function, modified to work with byte sequences for hashing with additional            parameters.

MAC_then_encrypt and decrypt_and_verify:
  Core functions for encrypting data with a given key and IV, and decrypting while verifying integrity using generated         tags.

generate_passwords:
  Generates potential passwords through a brute-force approach based on specific criteria, aiding in encryption                security.


# Testing Notes:
Due to the extensive computational time required to test the entire script (approximately two hours for full decryption      attempts), direct full-scale testing on my computer is not feasible. However, I have provided the test_encrypt_decrypt.py script that allows for testing of the main functions (MAC_then_encrypt and decrypt_and_verify) in isolation.
This script enables you to quickly verify that the encryption and decryption processes are functioning as expected.          Additionally, individual functions can be tested separately if needed.

# Known Bugs:
No bugs were found in my implementation of the algorithm.

# Additional Notes:
The implementation of cryptographic functions closely follows the guidelines provided in the assignment document, supplemented by insights from official documentation and community discussions.

Acknowledgments:
Python 3 Documentation: Extensively referenced for understanding library functionalities and cryptographic modules.
https://docs.python.org/3/
NIST Special Publication 800-185: Provided foundational knowledge for implementing and encoding schemes, respectively.
Stack Overflow: Offered practical solutions and optimizations for various cryptographic operations, enhancing the overall efficiency of the code.
