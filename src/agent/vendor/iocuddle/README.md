[![Workflow Status](https://github.com/enarx/iocuddle/workflows/test/badge.svg)](https://github.com/enarx/iocuddle/actions?query=workflow%3A%22test%22)
[![Average time to resolve an issue](https://isitmaintained.com/badge/resolution/enarx/iocuddle.svg)](https://isitmaintained.com/project/enarx/iocuddle "Average time to resolve an issue")
[![Percentage of issues still open](https://isitmaintained.com/badge/open/enarx/iocuddle.svg)](https://isitmaintained.com/project/enarx/iocuddle "Percentage of issues still open")
![Maintenance](https://img.shields.io/badge/maintenance-activly--developed-brightgreen.svg)

# iocuddle

`iocuddle` is a library for building runtime-safe `ioctl()` interfaces.

Existing approaches to interfacing with `ioctl`s from Rust rely on casting
and/or unsafe code declarations at the call site. This moves the burden of
safety to the consumer of the `ioctl` interface, which is less than ideal.

In contrast, `iocuddle` attempts to move the unsafe code burden to `ioctl`
definition. Once an `ioctl` is defined, all executions of that `ioctl` can
be done within safe code.

## Interfaces

`iocuddle` aims to handle >=99% of the kernel's `ioctl` interfaces.
However, we do not aim to handle all possible `ioctl` interfaces. We will
outline the different `ioctl` interfaces below.

### Classic Interfaces

Classic `ioctl` interfaces are those `ioctl`s which were created before
the modern interfaces we will see below. They basically allowed the full
usage of the `ioctl` libc function which is defined as this:

```rust
use std::os::raw::{c_int, c_ulong};
extern "C" { fn ioctl(fd: c_int, request: c_ulong, ...) -> c_int; }
```

This interface can take any number of any type of arguments and can return
any positive integer (with `-1` reserved for indicating an error in
combination with `errno`).

One major drawback of this interface is that it entirely punts on compiler
checking of type safety. A particular `request` is implicitly associated
with one or more types that are usually listed in the relevant `ioctl` man
page. If the programmer gets any of the types wrong, you end up with
corrupted memory.

The problems with this interface were recognized early on. Therefore,
most `ioctl`s support only a single argument to reduce complexity. But
this does not solve the problem of the lack of compiler-enforced type
safety.

`iocuddle` does not currently support `ioctl`s with multiple arguments.
Otherwise, classic `ioctl` interfaces can be defined and used via the
`Ioctl::classic()` constructor as follows:

```rust
use std::os::raw::{c_void, c_int, c_uint};
use iocuddle::*;

let mut file = std::fs::File::open("/dev/tty").unwrap_or_else(|_| std::process::exit(0));

// This is the simplest ioctl call. The request number is provided via the
// Ioctl::classic() constructor. This ioctl reads a C integer from the
// kernel by internally passing a reference to a c_int as the argument to
// the ioctl. This c_int is returned in the Ok status of the ioctl Result.
//
// Notice that since the state of the file descriptor is not modified via
// this ioctl, we define it using the Read parameter.
const TIOCINQ: Ioctl<Read, &c_int> = unsafe { Ioctl::classic(0x541B) };
assert_eq!(TIOCINQ.ioctl(&file).unwrap(), (0 as c_uint, 0 as c_int));

// This ioctl is similar to the previous one. It differs in two important
// respects. First, this raw ioctl takes an input argument rather than an
// output argument. This raw argument is a C integer *NOT* a reference to
// a C integer. Second, since this ioctl modifies the state of the file
// descriptor we use Write instead of Read.
//
// Notice that the return value of the TCSBRK.ioctl() call is the positive
// integer returned from the raw ioctl(), unlike the previous example. It
// is not the input argument type.
const TCSBRK: Ioctl<Write, c_int> = unsafe { Ioctl::classic(0x5409) };
assert_eq!(TCSBRK.ioctl(&mut file, 0).unwrap(), 0 as c_uint);

// `iocuddle` can also support classic ioctls with no argument. These
// always modify the file descriptor state, so the Write parameter is
// used.
const TIOCSBRK: Ioctl<Write, c_void> = unsafe { Ioctl::classic(0x5427) };
const TIOCCBRK: Ioctl<Write, c_void> = unsafe { Ioctl::classic(0x5428) };
assert_eq!(TIOCSBRK.ioctl(&mut file).unwrap(), 0);
assert_eq!(TIOCCBRK.ioctl(&mut file).unwrap(), 0);
```

### Modern Interfaces

In order to alleviate the type-safety problem with the classic interfaces,
the Linux kernel developed a new set of conventions for developing
`ioctl`s. We call these conventions the modern interface.

Modern `ioctl` interfaces always take a single reference to a struct or
integer and return `-1` on failure and `0` (or occasionally another
positive integer) on success. The `ioctl` request number is constructed
from four parameters:
  * a `group` (confusingly called `type` in the kernel macros)
  * a `nr` (number)
  * a `direction`
  * (the size of) a `type`

The `group` parameter is used as a namespace to group related `ioctl`s.
It is an integer value.

The `nr` parameter is an integer discriminator to uniquely identify the
`ioctl` within the `group`.

The `direction` parameter identifies which direction the data flows. If the
data flows from userspace to the kernel, this is the `write` `direction`.
If data flows from the kernel to userspace, this is the `read` `direction`.
Data which flows both ways is tagged with the `write/read` `direction`.

The `type` parameter identifies the type that should be used with this
`ioctl`. In the kernel C code this type is only directly used to perturb
the `ioctl` request number with the size of the type. `iocuddle`
additionally uses this parameter to provide type safety.

Defining modern `ioctl`s using `iocuddle` looks like this:

```rust
use iocuddle::*;

// Define the Group of KVM ioctls.
const KVM: Group = Group::new(0xAE);

// Define ioctls within the KVM group.
//
// The nr is passed to the direction-specific constructor.
const KVM_PPC_ALLOCATE_HTAB: Ioctl<WriteRead, &u32> = unsafe { KVM.write_read(0xa7) };
const KVM_X86_GET_MCE_CAP_SUPPORTED: Ioctl<Read, &u64> = unsafe { KVM.read(0x9d) };
const KVM_X86_SETUP_MCE: Ioctl<Write, &u64> = unsafe { KVM.write(0x9c) };
```

## Kernel Documentation

For the kernel documentation of the ioctl process, see the following file
in the kernel source tree: `Documentation/userspace-api/ioctl/ioctl-number.rst`

License: Apache-2.0
