use super::MountInfo;
use std::{
    fmt::{self, Display, Formatter},
    io,
    ops::{Deref, DerefMut},
    str::FromStr,
};

/// An element in an abtract representation of the mount tab that was read into memory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AbstractMountElement {
    /// An element which is a comment
    Comment(String),
    /// An element which is an empty line.
    Empty,
    /// An element which defines a mount point
    Mount(MountInfo),
}

impl Display for AbstractMountElement {
    fn fmt(&self, fmt: &mut Formatter) -> fmt::Result {
        match self {
            AbstractMountElement::Comment(ref comment) => fmt.write_str(comment),
            AbstractMountElement::Empty => Ok(()),
            AbstractMountElement::Mount(ref entry) => fmt.write_fmt(format_args!("{}", entry)),
        }
    }
}

impl From<String> for AbstractMountElement {
    fn from(comment: String) -> Self { AbstractMountElement::Comment(comment) }
}

impl From<()> for AbstractMountElement {
    fn from(_: ()) -> Self { AbstractMountElement::Empty }
}

impl From<MountInfo> for AbstractMountElement {
    fn from(info: MountInfo) -> Self { AbstractMountElement::Mount(info) }
}

/// Provides an abstract representation of the contents of a mount tab.
///
/// The use case for this type is to enable editing of the original file, or creating new copies,
/// in a type-safe manner. Each element is an individual line from the original file. Elements
/// may be inserted, removed, and replaced.
#[derive(Clone, Default, Debug, Eq, PartialEq)]
pub struct MountTab(pub Vec<AbstractMountElement>);

impl MountTab {
    pub fn iter_mounts(&self) -> impl Iterator<Item = &MountInfo> {
        self.0.iter().filter_map(|e| {
            if let AbstractMountElement::Mount(e) = e {
                Some(e)
            } else {
                None
            }
        })
    }

    pub fn iter_mounts_mut(&mut self) -> impl Iterator<Item = &mut MountInfo> {
        self.0.iter_mut().filter_map(|e| {
            if let AbstractMountElement::Mount(e) = e {
                Some(e)
            } else {
                None
            }
        })
    }

    pub fn push<E: Into<AbstractMountElement>>(&mut self, element: E) {
        self.0.push(element.into());
    }
}

impl Deref for MountTab {
    type Target = Vec<AbstractMountElement>;

    fn deref(&self) -> &Self::Target { &self.0 }
}

impl DerefMut for MountTab {
    fn deref_mut(&mut self) -> &mut Self::Target { &mut self.0 }
}

impl Display for MountTab {
    fn fmt(&self, fmt: &mut Formatter) -> fmt::Result {
        for entry in &self.0 {
            writeln!(fmt, "{}", entry)?;
        }

        Ok(())
    }
}

impl FromStr for MountTab {
    type Err = io::Error;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let mut entries = Vec::new();

        for line in input.lines() {
            let line = line.trim_start();
            if line.is_empty() {
                entries.push(AbstractMountElement::Empty);
            } else if line.starts_with('#') {
                entries.push(AbstractMountElement::Comment(line.to_owned()));
            } else {
                let info = line.parse::<MountInfo>()?;
                entries.push(AbstractMountElement::Mount(info));
            }
        }

        Ok(MountTab(entries))
    }
}
