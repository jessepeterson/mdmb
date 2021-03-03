# mdmb

mdmb — short for MDM Benchmark, à la [ab](https://httpd.apache.org/docs/2.4/programs/ab.html) — is a tool for simulating Apple devices interacting with Apple MDM servers.

*mdmb* creates sets of fake Apple devices and allows you to enroll in, connect to, and thereby interact with Apple MDM servers. Interactions include receiving and responding to MDM commands and some common device actions like installing profiles and responding to information commands.

The goal of this project is to facilitate testing of Apple MDM servers in various ways. I.e:

  - Load & scalability testing
  - MDM protocol testing & feature development
  - Monitoring & validation
  - CI/CD

## Limitations

### Device simulation

The device simulation tries to be *similar* to a real Apple device. As such *mdmb* simulates a device Keychain, Configuration Profile store, Profile and per-Profile Payload processing (for profile installation & removal), an MDM Client, and more which are used when interacting with Apple MDM servers.

That said, *mdmb*'s device simulation is only meant to serve its ability to test MDM servers. This means many MDM commands, Configuration Profile payloads, and other aspects of simulating devices are missing, incomplete, erroneous, out of scope, or otherwise broken.

### APNs

A key component of Apple MDM is Apple's Push Notification service (APNs). However, as we are only simulating devices we cannot authenticate to Apple's APNs service. Therefore this part of the MDM communication channel simply doesn't work. We generate fake [push tokens and push magic](https://developer.apple.com/documentation/devicemanagement/tokenupdaterequest?language=objc) as we enroll with the MDM server. As such the MDM server attempting to send push notifications to our simulated devices will not succeed. Even if the notifications were processed by Apple's servers `mdmb` wouldn't be able to *receive* those notifications anyway.

Because the MDM server can't signal the device to connect to it we instead simulate a device receiving a push notification by specifically requesting that it connect to the MDM server on demand, shown below.

### OTA & ADE enrollment

OTA & ADE (DEP) enrollments ostensibly validate the initial enrollment data signature against an Apple CA for which *only Apple devices* can recieve a certificate. Again becasue were merely simulate Apple devices we cannot obtain one of these certificates that are signed by Apple's Device CA. This means that in order to support OTA or ADE/DEP enrollments the MDM server must not have implemented or have disabled their device certificate validation. Practically this means simulated OTA and ADE enrollments are not supported.

## Getting started

### Installing & Building

### Create device(s)

The `devices-create` subcommand of `mdmb` will make new devices.

```bash
./mdmb devices-create
creating 1 device(s)
B0ECC518-1C7F-4DAF-B726-E7A169DB4CF8
```

Want to make more? Invoke `devices-create` again. Want to make *many* more? Use the `-n` switch and supply the number you want to create.

```bash
$ ./mdmb devices-create -n 3
creating 3 device(s)
DFB76ED4-4D29-4CB6-B930-1CAF8635868A
07998A4A-0D12-4818-BF6B-75F6C17B57B6
C432E77F-F167-4051-B3AB-A3B751C20AA9
```

### Enroll device(s)

The `devices-profiles-install` subcommand of `mdmb` tries to install profiles, including MDM enrollment profiles. You'll need to provide an Apple MDM enrollment profile of course. We also need to tell `mdmb` which devices to enroll by specifying the UUID. Note the `-uuids` argument comes before the subcommand name (`devices-profiles-install`). Note also you can specify "all" for the UUIDs or "-" to read them from stdin one line at a time.

```bash
$ ./mdmb -uuids B0ECC518-1C7F-4DAF-B726-E7A169DB4CF8 devices-profiles-install -f enroll.mobileconfig 
B0ECC518-1C7F-4DAF-B726-E7A169DB4CF8
level=info ts=2021-02-23T22:25:25.763628Z op=GetCACert error=null took=66.028014ms
[...snip...]
```

### Device(s) connect

The `devices-connect` subcommand of `mdmb` will direct already-enrolled devices to connect into the MDM server to check their command queue. This is similar to the devices receiving an APNs notification from the MDM server by way of Apple's APNs system.

```bash
$ ./mdmb -uuids all devices-connect
2021/03/02 12:08:14 device not enrolled (no identity uuid)
2021/03/02 12:08:14 device not enrolled (no identity uuid)
2021/03/02 12:08:14 device not enrolled (no identity uuid)
starting 1 workers for 1 iterations of 1 devices (1 connects)
.

Total MDM connects                1 (100%)
Errors                            0 (0%)
Total elapsed time                75.194793ms
Min MDM connect elapsed           75.147176ms
Max MDM connect elapsed           75.147176ms
Avg (mean) MDM connect elapsed    75.147176ms
Stddev MDM connect elapsed        0s
```

Here we see three devices not included in the test (because they were never enrolled) and our one enrolled device complete a checkin.

### List devices

The `devices-list` subcommand of `mdmb` lists all of the devices created in the above command.

```bash
$ ./mdmb devices-list
B0ECC518-1C7F-4DAF-B726-E7A169DB4CF8
DFB76ED4-4D29-4CB6-B930-1CAF8635868A
07998A4A-0D12-4818-BF6B-75F6C17B57B6
C432E77F-F167-4051-B3AB-A3B751C20AA9
```

#### Scripting devices

By combining commands you can script queuing device commands (i.e. to be connected to de-queued by the `devices-connect` subcommand later):

```bash
$ mdmb devices-list | xargs -n 1 ./tools/api/commands/device_information
```
