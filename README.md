
# RDPChecker

The purpose of this tool is to check RDP capabilities of a user on specific targets.

Programming concept was taken from [RDPassSpray](https://github.com/xFreed0m/RDPassSpray) and thus [RDPSpray](https://github.com/dafthack/RDPSpray).

## Requirements

- Linux with `xfreerdp` package
- argparse (pip)
- colorlog (pip)

## Usage

Test one host: `python3 RDPChecker.py -d crazy.local -u Hypnoze -p S3cr3t 10.0.0.1`

Test several hosts: `python3 RDPChecker.py -d crazy.local -u Hypnoze -p S3cr3t 10.0.0.1,10.0.2.2,192.168.1.25,172.26.5.15`

Test several hosts using file: `python3 RDPChecker.py -d crazy.local -u Hypnoze -p S3cr3t hosts.txt`


## Internal working

The python script use `xfreerdp` to attempt a RDP connection on the provided targets.


## Further work

- Pass-The-Hash
- Spraying multiple credentials at the same time
- Automatic spoofing of hostname (from RDPassSpray)
