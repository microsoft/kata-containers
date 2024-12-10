#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct FooA {}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all(serialize = "lowercase"))]
pub struct FooB {}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all(deserialize = "UPPERCASE"))]
pub struct FooC {}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all(serialize = "lowercase", deserialize = "UPPERCASE"))]
pub struct FooD {}
