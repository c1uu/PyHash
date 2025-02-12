import hashlib
# This module (named hashlib) implements a common interface to different secure hash
# including SHA1, SHA224, SHA256, SHA384, and SHA512, as well as MD5 algorithm


while True:

    hashvalue = input("* Enter a string to hash:")

    '''
    1. hashlib.md5(): It returns an utf-8 encoded version of the string
    2. The bytes() method in Python creates a sequence of bytes from strings or lists of integers
    3. hexdigest()  returns the digest as a string object containing only hexadecimal 
        digits. so the hash value is a hexadecimal string.
    '''

    # MD5:
    hashguess_md5 = hashlib.md5(bytes(hashvalue, 'utf-8'))
    hashguess_md5 = hashguess_md5.hexdigest()
    print("MD5: ", hashguess_md5)

    # sha-1:
    hashguess_sha1 = hashlib.sha1(bytes(hashvalue, 'utf-8'))
    hashguess_sha1 = hashguess_sha1.hexdigest()
    print("sha-1: ", hashguess_sha1)


    # sha-224:
    hashguess_sha224 = hashlib.sha224(bytes(hashvalue, 'utf-8'))
    hashguess_sha224 = hashguess_sha224.hexdigest()
    print("sha-224: ", hashguess_sha224)

    # sha-256:
    hashguess_sha256 = hashlib.sha256(bytes(hashvalue, 'utf-8'))
    hashguess_sha256 = hashguess_sha256.hexdigest()
    print("sha-256: ", hashguess_sha256)

    # sha-512:
    hashguess_sha512 = hashlib.sha512(bytes(hashvalue, 'utf-8'))
    hashguess_sha512 = hashguess_sha512.hexdigest()
    print("sha-512: ", hashguess_sha512)
