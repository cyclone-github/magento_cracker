import argparse
import nacl.pwhash
import binascii
import re

# magento v2 hash cracker
# this script is only for hashes formated like "hash:salt:3_32_2_67108864" which are ARGON2ID13_AGNOSTIC
# example hash:     ab5ebf8d273b085b6a60336198e0a5a2090fdc3e0606a678315c7274ab06e046:5PiKJRn28bBKoFMopMaaKuV47aJ6GzVg:3_32_2_67108864
# example password: Password@

# original script by Plum
# modified by cyclone with the following features:
# added flag "-wordlist" so script can check hashes against a wordlist instead of one password
# added flag "-hash" so script can check a hash list instead of one single hash

parser = argparse.ArgumentParser(description='Magento Argon2di hash verifier.')
parser.add_argument('-hash', '--hash-file', help='path to file containing hashes', type=str, required=True)
parser.add_argument('-wordlist', '--wordlist-file', help='path to password wordlist file', type=str, required=True)
args = parser.parse_args()

mlevel=nacl.pwhash.MEMLIMIT_INTERACTIVE
olevel=nacl.pwhash.OPSLIMIT_INTERACTIVE

with open(args.hash_file, 'r') as hash_file:
    for hash_string in hash_file:
        split = hash_string.strip().split(":")
        if len(split) != 3:
            print(f"Invalid hash format: {hash_string}")
            continue
        
        hashh, salt_b64, version = split
        salt = salt_b64[0:16].encode()
        versinfo = version.split("_")
        if len(versinfo) != 4:
            print(f"Invalid version format: {hash_string}")
            continue
        lenn = int(versinfo[1])
        ops = int(versinfo[2])
        mem = int(versinfo[3])
        
        with open(args.wordlist_file, 'r') as wordlist_file:
            for password in wordlist_file:
                password = password.strip().encode()
                verify = binascii.hexlify(nacl.pwhash.argon2id.kdf(size=lenn,password=password,salt=salt,opslimit=ops,memlimit=mem))
                if verify.decode() == hashh:
                    print(f"{hash_string.strip()}:{password.decode()}")

# end code
