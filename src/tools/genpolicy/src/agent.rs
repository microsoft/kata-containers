use serde::{Deserialize, Serialize};
use serde_repr::*;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Storage {
    pub driver: String,
    pub driver_options: Vec<String>,
    pub source: String,
    pub fstype: String,
    pub options: Vec<String>,
    pub mount_point: String,
    pub fs_group: Option<FSGroup>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FSGroup {
    pub group_id: i64,
    pub group_change_policy: FSGroupChangePolicy,
}

#[derive(Clone, Debug, Default, Serialize_repr, Deserialize_repr)]
#[repr(u8)]
pub enum FSGroupChangePolicy {
    #[default]
    Always = 0,
    OnRootMismatch = 1,
}
