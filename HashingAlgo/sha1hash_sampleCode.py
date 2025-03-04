import hashlib

sha1hash = input("[*] Enter sh1 Hash Value: ") # define the hash value you need to crack.
print(sha1hash) # print the hash value out.

filepath = "PasswordLists/repo.txt"
passlist = open(filepath, 'r') # open the password list
for password in passlist.readlines():   # read each line in password file (there is a '\n' at the end).
    password = password.strip('\n')     # remove the '\n' character from the readings.
    hashguess = hashlib.sha1(bytes(password, 'utf-8')).hexdigest() # convert the plaintext password to corresponding sha1 hash value.
    print(hashguess) # print out the hash candidate.

    # the following if statement check if there is a match between hash values
    if hashguess == sha1hash:
        print("[+] The Password is: " + str(password)) # find the hash value.
        quit()
    else:
        print("[-] Password guess" + str(password) + " does not match, trying next...")
