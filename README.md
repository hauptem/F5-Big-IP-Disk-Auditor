# F5 BIG-IP Disk Audit

![License](https://img.shields.io/badge/license-MIT-green)
![TMOS Version](https://img.shields.io/badge/TMOS-13.x%20--%2017.x-red)

Read-only disk space report for BIG-IP. Twelve checks covering partition and inode usage, boot volumes, largest files per volume, deleted files still held open, and removable ISO, EPSEC, UCS, qkview, core and pcap files. Each check cites the F5 article it is based on and shows the command it ran. Nothing is deleted or modified.

## Usage

```bash
chmod +x F5-Big-IP-Disk-Audit.sh
./F5-Big-IP-Disk-Audit.sh
```

Run as an Administrator with Advanced Shell access.

```
--no-color        disable ANSI color in terminal output
--log <path>      append a plain-text copy of the report
--html [<path>]   write a standalone HTML report instead of printing
--noconfirm       skip the confirmation prompt (alias: -y, --yes)
-h, --help        print usage and exit
```

## References

- [K14403: Maintaining disk space on the BIG-IP system](https://my.f5.com/manage/s/article/K14403)
- [K23607394: The /usr partition shows high disk space usage](https://my.f5.com/manage/s/article/K23607394)
- [K33265170: Deleting a boot location volume to free up disk space](https://my.f5.com/manage/s/article/K33265170)
- [K41517018: /var is nearly full, /var/log is not in /var](https://my.f5.com/manage/s/article/K41517018)
- [K000136089: No space left on /var partition even after removing large files](https://my.f5.com/manage/s/article/K000136089)
- [K34745165: Managing software images on the BIG-IP system](https://my.f5.com/manage/s/article/K34745165)
- [K21175584: Removing unnecessary OPSWAT EPSEC packages from the BIG-IP APM system](https://my.f5.com/manage/s/article/K21175584)
- [K000092603: Multiple EPSEC iso files in the system /config/filestore/files_d/Common_d/epsec_package_d/](https://my.f5.com/manage/s/article/K000092603)
- [K13132: Backing up and restoring BIG-IP configuration files with a UCS archive](https://my.f5.com/manage/s/article/K13132)

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Disclaimer

- This solution is **NOT** officially endorsed, supported, or maintained by F5 Inc.
- F5 Inc. retains all rights to their trademarks, including but not limited to "F5", "BIG-IP", "TMOS", and related marks
- This is an independent, community-developed solution that utilizes F5 products but is not affiliated with F5 Inc.
- For official F5 support and solutions, please contact F5 Inc. directly

**Technical Disclaimer:**

- This software is provided "AS IS" without warranty of any kind
- The authors and contributors are not responsible for any damages or issues that may arise from its use
- Always test thoroughly in non-production environments before deployment
- Review and understand all code before deploying to production systems

By using this software, you acknowledge that you have read and understood these disclaimers and agree to use this solution at your own risk.
