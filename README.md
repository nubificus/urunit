# urunit: A minimal init for Linux guests in urunc

This repository contains the code of `urunit`, a simple init process designed
for Linux guests running over [urunc](https://github.com/nubificus/urunc). It
acts as a reaper and correctly prepares and forwards command-line arguments
to the target application.

### Features

The key features of `urunit` are:

- Parsing and grouping multi-word arguments from Linux kernel boot parameters
- Launching and waiting for the target application until it terminates
- Reaping all zombie processes

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
