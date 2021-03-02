# mdmb

mdmb — short for MDM Benchmark, à la [ab](https://httpd.apache.org/docs/2.4/programs/ab.html) — is a tool for simulating Apple devices enrolling into Apple MDM servers.

The device simulation tries to be similar to a real Apple device. As such *mdmb* simulates a device Keychain, Configuration Profile store, Profile and per-Profile Payload processing for profile installation & removal, an MDM Client, and more which are used when interacting with Apple MDM servers.

The goal of this project is to facilitate testing of Apple MDM servers in various ways. I.e:

  - Load & scalability testing
  - CI/CD
  - MDM protocol testing & feature development
  - Monitoring & validation

### On APNs

A key component of Apple MDM is Apple's Push Notification service (APNs). However, as we are only simulating devices we cannot authenticate to Apple's APNs service. Therefore this part of the MDM communication channel simply doesn't work. We generate fake [push tokens and push magic](https://developer.apple.com/documentation/devicemanagement/tokenupdaterequest?language=objc) as we enroll with the MDM server. As such the MDM server attempting to send push notifications to our simulated devices will not succeed. Even if the notifications were processed by Apple's servers `mdmb` wouldn't be able to *receive* those notifications anyway.

Because the MDM server can't signal the device to connect to it we instead simulate a device receiving a push notification by specifically requesting that it connect to the MDM server on demand, shown below.

## Getting started

### Installing & Building

### Create device(s)

The `devices-create` subcommand of `mdmb` will make new devices.

```bash
./mdmb devices-create
1
B0ECC518-1C7F-4DAF-B726-E7A169DB4CF8
```

Want to make more? Invoke `devices-create` again. Want to make *many* more? Use the `-n` switch and supply the number you want to create.

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

The `devices-connect` subcommand of `mdmb` will direct already-enrolled devices to connect into the MDM server to check their command queue. This is similar to the device receiving an APNs notification from the MDM server by way of Apple's APNs system.

```bash
$ ./mdmb devices-connect
07998A4A-0D12-4818-BF6B-75F6C17B57B6
===> Connect
[...snip...]
```

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

By combining commands you can script queuing device commands (i.e. to be connected to de-queued by the `devices-connect` command later):

```bash
$ mdmb devices-list | xargs -n 1 ./tools/api/commands/device_information
```
