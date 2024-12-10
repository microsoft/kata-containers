#[derive(serde::Serialize, serde::Deserialize)]
pub enum FooA {
    #[serde(alias = "name")]
    Bar,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub enum FooB {
    #[serde(alias = "name_a")]
    #[serde(alias = "name_b")]
    Bar,
}
