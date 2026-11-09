# urunit: A minimal init for Linux guests in urunc

This repository contains the code of `urunit`, a simple init process designed
for Linux guests running over [urunc](https://github.com/nubificus/urunc). It
acts as a reaper and correctly prepares and forwards command-line arguments
to the target application.

### Features

The key features of `urunit` are:

- Parsing and grouping multi-word arguments from Linux kernel boot parameters.
- Launching and waiting for the target application until it terminates.
- Reaping all zombie processes.
- Setting the default route to eth0, if `URUNIT_DEFROUTE` environment variable
  is set.
- Reading and setting the environment variables for an application from a file.
- Reading and setting the execution environment configuration for a process from a file.
- Reading and mounting attached block devices defined in the configuration file.

## Building

Building `urunit` is as simple as running `make`, but make sure that `make` and
a C compiler is installed. In particular:

- `make static`: builds `urunit` as a statically-linked binary
- `make static_debug`: builds `urunit` as a statically-linked binary enabling debug messages
- `make dynamic`: builds `urunit` as a dynamically-linked binary
- `make dynamic_debug`: builds `urunit` as a dynamically-linked binary enabling debug messages


> **NOTE**: The default build target is `make static`, hence running `make`
> will build `urunit` statically.

## Usage

To use `urunit`, prefix it before the application you want to run.
For instance, to run a `ls` command:

```
urunit ls
```

There are no arguments specifically for `urunit`. The first argument is treated
as the application to execute with the rest passed as arguments to that
application.

### Multi-word CLI arguments

One of the main purposes of `urunit` is to support multi-word CLI arguments
passed via `urunc` to an application in a Linux VM. Since the Linux kernel
cannot differentiate multi-word arguments in boot parameters (treating each
word as a separate argument), `urunc` follows a convention: multi-word arguments
are enclosed in single quotes. `urunit` then reassembles them properly before
execution.

For example, running:

```
urunit echo `hello world`
```

will result in `echo` receiving a single argument: `hello world`.

### Urunit configuration file

In order to configure the execution environment for an application, `urunit`
accepts a specific configuration file. The configuration file can contain the
following information:

- The list of the environment variables to set for the application
- The configuration for the process execution environment.
- The application command to execute, when `urunit` is started without a
  command line (optional).
- The list of mounts of block devices. Each block device is defined by its
  serial id and it will get mounted in the defined mountpoint.
- The network configuration (IP address, gateway and netmask) for guests
  that can not get it from the kernel command line (optional).

The file can be specified to `urunit` setting the `URUNIT_CONFIG`
environment variable with the path to the configuration file.

Every section marker and value record is terminated by NUL (`\\0`), which
allows newlines to be preserved in environment variables, paths and application
arguments. The supported format of the configuration file is the following
(the `\\0` terminators are shown explicitly):

```
UES\0
<environment variable>\0
...
UEE\0
UCS\0
UID:<uid_for_the_application>\0
GID:<gid_for_the_application>\0
WD:<working_directory>\0
ARC:<number_of_application_arguments>\0
ARV:<application_argument>\0
...
UCE\0
UBS\0
ID:<serial_id>\0
MP:<mountpoint>\0
...
UBE\0
UNS\0
IP:<ipv4_address>\0
GW:<gateway>\0
MSK:<netmask>\0
UNE\0
```

Inside the `UCS` section, the application command is optional: `ARC` holds the
number of arguments and is followed by exactly that many `ARV` lines, one per
argument, each taken verbatim. It is used when `urunit` is started without a
command line, in which case the command from the configuration is executed.

The `UNS` section is optional and provides the network configuration for
guests that can not get it from the kernel command line: `IP` is the IPv4
address, `GW` the gateway and `MSK` the netmask. An empty value (e.g. `IP:`)
leaves the field unset.

## Installation

Using one of the following methods, we can install `urunit` either in a
container image or in any other supported target.

### Building from source

Simply running:

```
make
make install
```

will build and install `urunit` at /usr/local/bin/`. You can override the
installation path using the `PREFIX` variable.

### Downloading prebuilt binaries

Each release includes statically linked binaries for x86_64 and aarch64.
Download and install with:

```
wget -O /usr/local/bin/urunit https://github.com/nubificus/urunit/releases/download/v0.1.0/urunit_x86_64
chmod +x /usr/local/bin/urunit
```

### Using a container image

For easier distribution of `urunit`, the
`harbor.nbfc.io/nubificus/urunit:latest` contains a statically built version of `urunit` at `/urunit`. To extract it into another container:

```
FROM harbor.nbfc.io/nubificus/urunit:latest AS urunit
...
COPY --from=urunit /urunit /urunit
```
