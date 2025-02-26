import hashlib
import os

def md5_hash(data):
    return hashlib.md5(data.encode('utf-8')).hexdigest()

def sha1_hash(data):
    return hashlib.sha1(data.encode('utf-8')).hexdigest()

# Get the absolute path of the script's directory
script_dir = os.path.dirname(os.path.abspath(__file__))

# Construct the correct path to repo.txt inside PasswordLists
PASSWORD_FILE = os.path.join(script_dir, "..", "PasswordLists", "repo.txt")

def run_hash_breaker(target_hash, salt, password_file):
    # List of hashing functions and their combinations to test
    hash_attempts = [
        ("SHA1(password + salt) -> MD5", lambda p, s: md5_hash(sha1_hash(p + s))),
        ("SHA1(salt + password) -> MD5", lambda p, s: md5_hash(sha1_hash(s + p))),
        ("MD5(password + salt) -> SHA1 -> MD5", lambda p, s: md5_hash(sha1_hash(md5_hash(p + s)))),
        ("MD5(salt + password) -> SHA1 -> MD5", lambda p, s: md5_hash(sha1_hash(md5_hash(s + p)))),
        ("MD5(password + salt) -> MD5", lambda p, s: md5_hash(md5_hash(p + s))),
        ("MD5(salt + password) -> MD5", lambda p, s: md5_hash(md5_hash(s + p))),
        ("Double SHA1 -> MD5 (password + salt)", lambda p, s: md5_hash(sha1_hash(sha1_hash((p + s))))),
        ("Double SHA1 -> MD5 (salt + password)", lambda p, s: md5_hash(sha1_hash(sha1_hash((s + p))))),
        ("Triple MD5 (password + salt)", lambda p, s: md5_hash(md5_hash(md5_hash((p + s))))),
        ("Triple MD5 (salt + password)", lambda p, s: md5_hash(md5_hash(md5_hash((s + p))))),
        ("SHA1(password + salt) -> MD5 -> MD5", lambda p, s: md5_hash(md5_hash(sha1_hash(p + s)))),
        ("SHA1(salt + password) -> MD5 -> MD5", lambda p, s: md5_hash(md5_hash(sha1_hash(s + p)))),
        ("Double SHA1 -> Double MD5 (password + salt)", lambda p, s: md5_hash(md5_hash(sha1_hash(sha1_hash(p + s))))),
        ("Double SHA1 -> Double MD5 (salt + password)", lambda p, s: md5_hash(md5_hash(sha1_hash(sha1_hash(s + p))))),
        ("Salt in middle -> SHA1 -> MD5", lambda p, s: md5_hash(sha1_hash(p[:len(p)//2] + s + p[len(p)//2:]))),
        ("Repeated salt -> SHA1 -> MD5", lambda p, s: md5_hash(sha1_hash(s + p + s)))
    ]

    # Load passwords from the file
    try:
        with open(password_file, 'r') as file:
            passwords = [line.strip() for line in file.readlines() if line.strip()]
    except FileNotFoundError:
        print(f"The file '{password_file}' was not found.")
        return

    # Testing each password from the list
    found = False
    for password in passwords:
        salted_password = password + salt  # Only apply the salt to the original password
        for description, hash_func in hash_attempts:
            result = hash_func(salted_password, "")  # No additional salting after the first round
            print(f"Testing {description} with password '{password}': {result}")
            if result == target_hash:
                print(f"\nMatch found with password '{password}' using method: {description}")
                found = True
                break
        if found:
            break

    if not found:
        print("\nNo matching hash found with the tested combinations.")

# Driver function
if __name__ == "__main__":
    TARGET_HASH = "8493ec1c2d24df126f1a9753e0311aa4"
    SALT = "dog"
    run_hash_breaker(TARGET_HASH, SALT, PASSWORD_FILE)
