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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SerializedFsGroup {
    pub group_id: u32,
    pub group_change_policy: u32,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Device {
    pub id: String,
    pub type_: String,
    pub vm_path: String,
    pub container_path: String,
    pub options: Vec<String>,
}
