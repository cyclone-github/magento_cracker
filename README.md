[![Readme Card](https://github-readme-stats.vercel.app/api/pin/?username=cyclone-github&repo=magento_cracker&theme=gruvbox)](https://github.com/cyclone-github/)

### NOTE: plum has released a Magento converter tool which allows Magento v2 & v3 hashes to be run as standard argon2id with jtr or argon_cracker: https://github.com/PlumLulz/magento_converter

# Cyclone's Magento v2 Hash Cracker
python3 script to verify Magento v2 hashes appended with ":2" or ":3_" (which are argon2id hashes).

_**This tool was proudly the first publicly released cracker for this custom algo.**_

### Usage:
- python3 magento_v2_argon2id.py -hash hashes.txt -wordlist wordlist.txt

### Credits:
- original script by Plum https://github.com/PlumLulz
- modified by cyclone with the following features:
  - added flag "-wordlist" so script can check hashes against a wordlist instead of one password
  - added flag "-hash" so script can check a hash list instead of one single hash
  - added ability to correctly check, parse & crack both :2 & :3 Magento v2 hashes

### Change Log:
- https://github.com/cyclone-github/magento_cracker/blob/main/CHANGELOG.md
