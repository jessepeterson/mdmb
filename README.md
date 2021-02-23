# mdmb

mdmb — short for MDM Benchmark, à la [ab](https://httpd.apache.org/docs/2.4/programs/ab.html) — is a tool for simulating Apple device enrollments into Apple MDM servers.

The goal of this project is to facilitate testing of Apple MDM servers in various ways. I.e:

  - Load & scalability testing
  - CI/CD
  - MDM protocol & feature development
  - MDM server monitoring
  - Automated testing

## Getting started

### Installing & Building

### Create device(s)

The `devices-create` subcommand of `mdmb` will make new devices.

```bash
./mdmb devices-create
1
B0ECC518-1C7F-4DAF-B726-E7A169DB4CF8
```

Want to make more? Just invoke `devices-create` again. Want to make many more? Use the `-n` switch and supply the number you want to create.

```bash
$ ./mdmb devices-create -n 3
3
DFB76ED4-4D29-4CB6-B930-1CAF8635868A
07998A4A-0D12-4818-BF6B-75F6C17B57B6
C432E77F-F167-4051-B3AB-A3B751C20AA9
```

### Enroll device(s)

The `devices-enroll` subcommand of `mdmb` try to enroll all devices. Note you'll need to provide an Apple MDM enrollment profile.

```bash
$ ./mdmb devices-enroll -file enroll.mobileconfig 
B0ECC518-1C7F-4DAF-B726-E7A169DB4CF8
level=info ts=2021-02-23T22:25:25.763628Z op=GetCACert error=null took=66.028014ms
[...snip...]
```

### Device(s) connect

The `devices-connect` subcommand of `mdmb` will direct already-enrolled devices to connect into the MDM server to check their command queue.

```bash
$ ./mdmb devices-connect
07998A4A-0D12-4818-BF6B-75F6C17B57B6
===> Connect
[...snip...]
```
