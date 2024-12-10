[![Workflow Status](https://github.com/enarx/codicon/workflows/test/badge.svg)](https://github.com/enarx/codicon/actions?query=workflow%3A%22test%22)
[![Average time to resolve an issue](https://isitmaintained.com/badge/resolution/enarx/codicon.svg)](https://isitmaintained.com/project/enarx/codicon "Average time to resolve an issue")
[![Percentage of issues still open](https://isitmaintained.com/badge/open/enarx/codicon.svg)](https://isitmaintained.com/project/enarx/codicon "Percentage of issues still open")
![Maintenance](https://img.shields.io/badge/maintenance-activly--developed-brightgreen.svg)

# codicon

Traits for encoding and decoding.

This crate provides generic traits for encoding and decoding to a
`std::io::Read` or `std::io::Write` type, respectively.

We often need to express that a type can be encoded or decoded. We
also need a way to express the type of the encoding or decoding as
well as parameters that may be used for that encoding or decoding.
This tiny crate solves this problem.

## Examples

Let's say we want `u8` to be able to be encoded in a (made up) format `Foo`
which simply writes the byte without modification. We can express this
encoding as follows:

```rust
use codicon::*;

struct Foo;

impl Encoder<Foo> for u8 {
    type Error = std::io::Error;

    fn encode(&self, mut writer: impl Write, params: Foo) -> std::io::Result<()> {
        writer.write_all(std::slice::from_ref(self))?;
        Ok(())
    }
}

let mut buf = [0u8; 1];
7u8.encode(&mut buf.as_mut(), Foo).unwrap();
assert_eq!(buf[0], 7u8);
```

Note that we used a unit struct because the `Foo` encoding doesn't take any
options. But if you wanted to specify encoding options, you could just make
a type with parameters.

Decoding works the same as encoding:

```rust
use codicon::*;

struct Foo;

impl Decoder<Foo> for u8 {
    type Error = std::io::Error;

    fn decode(mut reader: impl Read, params: Foo) -> std::io::Result<Self> {
        let mut byte = 0u8;
        reader.read_exact(std::slice::from_mut(&mut byte))?;
        Ok(byte)
    }
}

let buf = [7u8; 1];
assert_eq!(u8::decode(&mut buf.as_ref(), Foo).unwrap(), 7u8);
```

License: Apache-2.0
