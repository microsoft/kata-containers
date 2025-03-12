#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename = "name")]
pub struct FooA {}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename(serialize = "ser_name"))]
pub struct FooB {}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename(deserialize = "de_name"))]
pub struct FooC {}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename(serialize = "ser_name", deserialize = "de_name"))]
pub struct FooD {}
