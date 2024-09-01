### version 0.3.0; 2023-04-07.1045
```
added multithreading support (uses 1 thread per hash and up to all available CPU threads)
added logic to dedup hash list
added keyboard interrupt to force close program when pressing ctrl+c twice
added code comments & runtime metrics
```
### version 0.2.2; 2023-04-06.1800; initial github release
```
original script by Plum https://github.com/PlumLulz
modified by cyclone with the following features:
added flag "-wordlist" so script can check hashes against a wordlist instead of one password
added flag "-hash" so script can check a hash list instead of one single hash
added ability to correctly check, parse & crack both :2 & :3 Magento v2 hashes
```