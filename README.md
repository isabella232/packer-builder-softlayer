This repository is a fork of [leonidlm/packer-builder-softlayer](https://github.com/leonidlm/packer-builder-softlayer).

# SoftLayer Builder (for packer.io)

The softlayer builder is able to create new images for use with SoftLayer. The builder takes a source image (identified by it's global ID or reference name), runs any provisioning necessary on the image after launching it, then snapshots it into a reusable image. This reusable image can then be used as the foundation of new servers that are launched within SoftLayer.

The builder does not manage images. Once it creates an image, it is up to you to use it or delete it.

## Install

Download and build Packer from source as described [here](https://github.com/mitchellh/packer#developing-packer).

Next, clone this repository into `$GOPATH/src/github.com/leonidlm/packer-builder-softlayer`.  Then build the packer-softlayer-builder binary:

```
cd $GOPATH/src/github.com/leonidlm/packer-builder-softlayer
go build -o /usr/local/packer/packer-builder-softlayer main.go
```

Now [configure Packer](http://www.packer.io/docs/other/core-configuration.html) to pick up the new builder:

```
{
  "builders": {
    "softlayer": "/usr/local/packer/packer-builder-softlayer"
  }
}
```

## Basic Example

The example below is fully functional and will create a basic centos 6 image with dnsmasq installed (only the __api_key__ and __username__ are missing):

```JSON
{
  "provisioners": [
    {
      "type": "shell",
      "inline": [
        "sudo yum install -y dnsmasq"
      ]
    }
  ],
  "builders": [{
    "type": "softlayer",
    "api_key": "",
    "username": "",
    "datacenter_name": "ams01",
    "base_os_code": "CENTOS_6_64",
    "image_name": "packer-centos-{{isotime}}",
    "image_description": "centos image created by packer at {{isotime}}",
    "image_type": "flex",
    "instance_name": "packer-centos-{{isotime}}",
    "instance_domain": "provisioning.com",
    "instance_cpu": 1,
    "instance_memory": 1024,
    "instance_network_speed": 10,
    "instance_disk_capacity": 25,
    "ssh_port": 22,
    "ssh_timeout": "15m",
    "instance_state_timeout": "25m"
  }]
}
```

If you are willing to use your own image as your starting point, you can specify `base_image_id` instead of `base_os_code`.

## Configuration Reference

The reference of available configuration options is listed below.

### Required parameters:

 * `username` (string) - The user name to use to access your account. If unspecified, the value is taken from the SOFTLAYER_USER_NAME environment variable.
 * `api_key` (string) - The api key defined for the chosen user name. You can find what is your api key at the account->users tab of the SoftLayer web console. If unspecified, the value is taken from the SOFTLAYER_API_KEY environment variable.
 * `image_name` (string) - The name of the resulting image that will appear in your account. This must be unique. To help make this unique, use a function like timestamp.
 * `base_image_id` (string) - The ID of the base image to use (usually defined by the `globalIdentifier` or the `uuid` fields in SoftLayer API). This is the image that will be used for launching a new instance. 
 __NOTE__ that if you choose to use this option, you must specify a private key using `ssh_private_key_file` (described below).
 To view all of your currently available images, run:

```SHELL
 curl https://<username>:<api_key>@api.softlayer.com/rest/v3/SoftLayer_Account/getVirtualDiskImages.json
```

 * `base_os_code` (string) - If you would like to start from a pre-installed SoftLayer OS image, you can specify it's reference code. 
 __NOTE__ that you can use only one of `base_image_id` or `base_os_code` per builder configuration.
 To view all of the currently available pre-installed os images, run:

```SHELL
 curl https://<username>:<api_key>@api.softlayer.com/rest/v3/SoftLayer_Account/getCreateObjectOptions.json | grep operatingSystemReferenceCode
```

### Optional parameters:
 * `datacenter_name` (string) - The code name of the region to launch the instance in. Consequently, this is the region where the image will be available. This defaults to "ams01"
 * `image_description` (string) - The description text which will be available for the resulting image. Defaults to "Instance snapshot. Generated by packer.io"
 * `image_type` (string) - The type of the image to create; either "flex" or "standard" (experimental). Defaults to "flex".
 * `instance_name` (string) - The name assigned to the instance. Default to "packer-softlayer-<EPOCH TIME>"
 * `instance_domain` (string) - The domain assigned to the instance. Defaults to "provisioning.com"
 * `instance_cpu` (string) - The amount of CPUs assigned to the instance. Defaults to 1
 * `instance_memory` (string) - The amount of Memory (in bytes) assigned to the instance. Defaults to 1024
 * `instance_network_speed` (string) - The network uplink speed, in megabits per second, which will be assigned to the instance. Defaults to 10
 * `instance_disk_capacity` (string) - The amount of Disk capacity (in gigabytes) assigned to the instance. Defaults to 25
 * `ssh_port` (string) - The port that SSH will be available on. Defaults to port 22
 * `ssh_timeout` (string) - The time to wait for SSH to become available before timing out. The format of this value is a duration such as "5s" or "5m". The default SSH timeout is "1m". Defaults to "15m"
 * `ssh_private_key_file` (string) - Use this ssh private key file instead of a generated ssh key pair for connecting to the instance.
 * `ssh_key_id` (string) - Attach this public key to the instance. Requires `ssh_private_key_file` for connecting.
 * `instance_state_timeout` (string) - The time to wait, as a duration string, for an instance or image snapshot to enter a desired state (such as "active") before timing out. The default state timeout is "25m"

As already stated above, a good way of reviewing the available options is by inspecting the output of the following API call:

```SHELL
 curl https://<username>:<api_key>@api.softlayer.com/rest/v3/SoftLayer_Account/getCreateObjectOptions.json
```

## Contribute

New contributors are always welcome! 
When in doubt please feel free to ask questions, just [Create an issue](https://github.com/leonidlm/packer-builder-softlayer/issues/new) with your enquiries.

### Development Environment

The Vagrantfile creates a development environment with Go and packer checked out and built. Type "vagrant up" to bring up the environment and then "vagrant ssh" to log in. The packer-builder-softlayer directory on the host is shared to the guest VM, and packer-builder-softalyer is built during "vagrant up". The SL_USERNAME and SL_API_KEY environment variables from your host machine are propagated to the VM. 

To run the unit tests, execute "go test ./..." from the root project directory.

### TODO
* Add tests (especially for the client, however other parts of the code are important too)
* Configure travis CI or any alternative to automatically test and build the code
* Provide an easier way to install (with no need to compile from source)
* Add an option to configure multiple disks for the instance

