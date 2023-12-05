use serde::{Deserialize, Serialize, Serializer, Deserializer};
use core::sync::atomic;
use std::collections::HashMap;
use std::hash::BuildHasherDefault;
use std::collections::hash_map::DefaultHasher;

#[derive(Clone, Debug , Serialize, Deserialize)] // todo: figure out how to make this work
// #[cfg_attr(feature = "with-serde", derive(::serde::Serialize, ::serde::Deserialize))]
// @@protoc_insertion_point(message:grpc.Storage)
// #[derive(PartialEq,Clone,Default,Debug)]
// #[cfg_attr(feature = "with-serde", serde(default))]
pub struct Storage {
    pub driver: String,
    pub driver_options: Vec<String>,
    pub source: String,
    pub fstype: String,
    pub options: Vec<String>,
    pub mount_point: String,
    pub fs_group: Option<SerializedFsGroup>,
    // special fields
    // #[cfg_attr(feature = "with-serde", serde(skip))]
    // @@protoc_insertion_point(special_field:grpc.Storage.special_fields)
    pub special_fields: SpecialFields,
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct MessageField<T>(pub Option<Box<T>>);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SerializedFsGroup {
    pub group_id: u32,
    pub group_change_policy: u32,
}

#[derive(Default, Debug, Serialize)]
pub struct SpecialFields {
    unknown_fields: UnknownFields,
    cached_size: CachedSize,
}

impl<'de> Deserialize<'de> for SpecialFields {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let unknown_fields = UnknownFields::default();
        let cached_size = CachedSize::default();
        Ok(SpecialFields {
            unknown_fields,
            cached_size,
        })
    }
}

impl Clone for SpecialFields {
    fn clone(&self) -> Self {
        SpecialFields {
            unknown_fields: self.unknown_fields.clone(),
            cached_size: CachedSize::default(),
        }
    }
}

impl Serialize for UnknownFields {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Implement serialization logic here
        // ...
        serializer.serialize_unit()
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct UnknownFields {
    /// The map.
    //
    // `Option` is needed, because HashMap constructor performs allocation,
    // and very expensive.
    //
    // We use "default hasher" to make iteration order deterministic.
    // Which is used to make codegen output deterministic in presence of unknown fields
    // (e. g. file options are represented as unknown fields).
    // Using default hasher is suboptimal, because it makes unknown fields less safe.
    // Note, Google Protobuf C++ simply uses linear map (which can exploitable the same way),
    // and Google Protobuf Java uses tree map to store unknown fields
    // (which is more expensive than hashmap).
    fields: Option<Box<HashMap<u32, UnknownValues, BuildHasherDefault<DefaultHasher>>>>,
}

#[derive(Clone, PartialEq, Eq, Debug, Default, Hash)]
pub(crate) struct UnknownValues {
    /// 32-bit unknowns
    pub(crate) fixed32: Vec<u32>,
    /// 64-bit unknowns
    pub(crate) fixed64: Vec<u64>,
    /// Varint unknowns
    pub(crate) varint: Vec<u64>,
    /// Length-delimited unknowns
    pub(crate) length_delimited: Vec<Vec<u8>>,
}

#[derive(Debug, Default, Serialize)]
pub struct CachedSize {
    size: atomic::AtomicUsize,
}