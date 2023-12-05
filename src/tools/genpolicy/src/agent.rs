use serde::{Deserialize, Serialize};

#[derive(Clone, Debug , Serialize, Deserialize)]
pub struct Storage {
    pub driver: String,
    pub driver_options: Vec<String>,
    pub source: String,
    pub fstype: String,
    pub options: Vec<String>,
    pub mount_point: String,
    pub fs_group: Option<SerializedFsGroup>,
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct MessageField<T>(pub Option<Box<T>>);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SerializedFsGroup {
    pub group_id: u32,
    pub group_change_policy: u32,
}