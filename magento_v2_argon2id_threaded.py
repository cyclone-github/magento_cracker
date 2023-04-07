import argparse
import nacl.pwhash
import binascii
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor

# magento v2 argon2id hash cracker

# this script can crack both :2 ARGON2ID13 & :3 ARGON2ID13_AGNOSTIC hashes
# example :2 hash:   a0f9f007c538cccdc8a809d76b5fc8f9b372b3c7ade7dc8f74e4aef709b727df:xBOgXnu843dmyzRM:2
# example password: Password@
# example :3 hash:  ab5ebf8d273b085b6a60336198e0a5a2090fdc3e0606a678315c7274ab06e046:5PiKJRn28bBKoFMopMaaKuV47aJ6GzVg:3_32_2_67108864
# example password: Password@

# # original script by Plum https://github.com/PlumLulz

# modified by cyclone https://github.com/cyclone-github/magento_cracker with the following features:

# version 0.2.2; 2023-04-06.1800
# added flag "-wordlist" so script can check hashes against a wordlist instead of one password
# added flag "-hash" so script can check a hash list instead of one single hash
# added ability to correctly check, parse & crack both :2 & :3 Magento v2 hashes

# version 0.3.0; 2023-04-07.1045
# added multithreading support (uses 1 thread per hash and up to all available CPU threads)
# added logic to dedup hash list
# added keyboard interrupt to force close program when pressing ctrl+c twice
# added code comments & runtime metrics

# parse CLI flags
parser = argparse.ArgumentParser(description='Magento Argon2di hash verifier.')
parser.add_argument('-hash', '--hash-file', help='path to file containing hashes', type=str, required=True)
parser.add_argument('-wordlist', '--wordlist-file', help='path to password wordlist file', type=str, required=True)
args = parser.parse_args()

# set memory and operation limits for nacl.pwhash
mlevel = nacl.pwhash.MEMLIMIT_INTERACTIVE
olevel = nacl.pwhash.OPSLIMIT_INTERACTIVE

# process hash / password
def verify_password(hash_string, password):
    # parse hash string
    split = hash_string.strip().split(":")
    if len(split) != 3:
        print(f"Invalid hash format: {hash_string}")
        return

    # extract hash components
    hashh, salt_b64, version = split
    if version == "2" or version == "3":
        version += "_32_2_67108864"
        hash_string = f"{hashh}:{salt_b64}:{version}"

    salt = salt_b64[0:16].encode()
    versinfo = version.split("_")
    if len(versinfo) != 4:
        print(f"Invalid version format: {hash_string}")
        return
    lenn = int(versinfo[1])
    ops = int(versinfo[2])
    mem = int(versinfo[3])

    # verify password
    password = password.strip().encode()
    verify = binascii.hexlify(nacl.pwhash.argon2id.kdf(size=lenn, password=password, salt=salt, opslimit=ops, memlimit=mem))
    if verify.decode() == hashh:
        print(f"{hash_string.strip()}:{password.decode()}")

# process hash
def process_hash(hash_string, passwords):
    lines_processed = 0
    for password in passwords:
        verify_password(hash_string, password)
        lines_processed += 1
    return lines_processed

try:
    start_time = time.time()

    # read wordlist file
    with open(args.wordlist_file, 'r') as wordlist_file:
        passwords = [password.strip() for password in wordlist_file]

    # read hash file
    with open(args.hash_file, 'r') as hash_file:
        num_threads = max(os.cpu_count() or 1, 1)
        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            # deduplicate hashes
            hash_strings = list(set([hash_string.strip() for hash_string in hash_file]))
            num_hashes = len(hash_strings)
            actual_threads = min(num_threads, num_hashes)
            sys.stderr.write(f"Processing {num_hashes} uniq hashes using {actual_threads} threads...\n\n")
            tasks = [executor.submit(process_hash, hash_string, passwords) for hash_string in hash_strings]
            total_lines_processed = 0
            for task in tasks:
                total_lines_processed += task.result()

    # print runtime metrics
    end_time = time.time()
    elapsed_time = end_time - start_time
    lines_per_second = total_lines_processed / elapsed_time

    sys.stderr.write(f"\nFinished running {num_hashes} hashes\n")
    sys.stderr.write(f"Processed {total_lines_processed} total lines in {elapsed_time:.2f} sec, {lines_per_second:.2f} lines/sec\n")

# force close script if CTRL+C is pressed
except KeyboardInterrupt:
    sys.stderr.write("Interrupted by user. Exiting...\n")
    os._exit(1)

# end code
