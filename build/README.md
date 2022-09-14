# Build w2c-letsencrypt-esxi VIB & Offline Bundle

The `build.sh` bash script includes the commands needed to generate the VIB and Offline Bundle files. It relies on the [lamw/vibauthor](https://hub.docker.com/r/lamw/vibauthor/) Docker container and uses the files in this repository.

After copying all files to the container, `create_vib.sh` runs in the container to actually build the ESXi bundle.

Here is a sample output of the script:

```bash
/bin/bash ./build.sh

Untagged: letsencrypt-esxi:latest
Deleted: sha256:3009ff3662db9c3b60157bc0fff1a0c936ec6e301103c5efc50eca113c744b5f
Deleted: sha256:daff819de772ed33d7de07701d8235453872365586a49c503f5194555424cda1
Deleted: sha256:e0f946d4136a08d7d87bbce58af17226b019cbd97f3fec018861f155ded84257
Sending build context to Docker daemon  1.261MB
Step 1/4 : FROM lamw/vibauthor
 ---> a673ffe4ba43
Step 2/4 : COPY . letsencrypt-esxi
 ---> 6197d7c06029
Step 3/4 : RUN /bin/bash letsencrypt-esxi/build/create_vib.sh
 ---> Running in 3f6f149cfed4
WARNING: extensibility rules check failed, but was ignored because of --force.
VIB (web-wack-creations_bootbank_w2c-letsencrypt-esxi_1.0.0-0.0.0) failed a check of extensibility rules for acceptance level 'community': [u'(line 23: col 0) Element vib failed to validate content'].
Successfully created w2c-letsencrypt-esxi.vib.
Successfully created w2c-letsencrypt-esxi-offline-bundle.zip.
**** Info for VIB: w2c-letsencrypt-esxi.vib ****
VIB Format:             2.0.0
VIB ID:                 web-wack-creations_bootbank_w2c-letsencrypt-esxi_1.0.0-0.0.0
VIB Type:               bootbank
Name:                   w2c-letsencrypt-esxi
Version:                1.0.0-0.0.0
Vendor:                 web-wack-creations
Summary:                [Fling] Let's Encrypt for ESXi
Description:            Let's Encrypt for ESXi
Creation Date:          2022-05-29 15:03:02+00:00
Provides:
        w2c-letsencrypt-esxi = 1.0.0-0.0.0
Depends:
Conflicts:
Replaces:
        w2c-letsencrypt-esxi << 1.0.0-0.0.0
Software Tags:          []
MaintenanceMode:        remove/update: False, installation: False
Signed:                 False
AcceptanceLevel:        community
LiveInstallAllowed:     True
LiveRemoveAllowed:      True
CimomRestart:           False
StatelessReady:         True
Overlay:                False
Payloads:
  Name            Type        Boot Size        Checksums
  payload1        vgz         0    26555       sha-256 5df898d1217a9167e2e9f7d8e8d2e2a21bcd1acad0f7b74fa9d793c85e728bf3
                                               sha-1 76834e1ea72f6e306d10a411eccc777faa2e8ddf
Removing intermediate container 3f6f149cfed4
 ---> f2f14c706557
Step 4/4 : CMD ["/bin/bash"]
 ---> Running in fc567d964e69
Removing intermediate container fc567d964e69
 ---> 5c3b069e2f7a
Successfully built 5c3b069e2f7a
Successfully tagged letsencrypt-esxi:latest
```

Upon success, there should be a new directory named `artifacts` which contains the resulting VIB and Offline Bundle files.

```bash
ls -l ../artifacts

-rw-r--r-- 1 root root 30K May 29 15:04 w2c-letsencrypt-esxi-offline-bundle.zip
-rw-r--r-- 1 root root 28K May 29 15:04 w2c-letsencrypt-esxi.vib
```

## Possible Pitfalls

As the [lamw/vibauthor](https://hub.docker.com/r/lamw/vibauthor/) container builds on CentOS 6, Docker requires a specific `vsyscall` setting to be set in the kernel of the host system that might no longer be the case if a more recent Linux kernel is used. E.g., on a recent version of Debian, running the container will result in a SegFault due to [bug 852620](https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=852620). If you encounter this problem, it can be [fixed](https://salsa.debian.org/kernel-team/linux/commit/74f87b226a1267b837d98a5d46824f9b5629962e) by setting `vsyscall=emulate`:

`vi /etc/default/grub`

```bash
GRUB_CMDLINE_LINUX_DEFAULT="quiet vsyscall=emulate"
```

```bash
update-grub
reboot
```
Anything past Debian `stretch` appears to need this set.
