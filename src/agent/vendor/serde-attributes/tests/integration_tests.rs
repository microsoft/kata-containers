#[cfg(feature = "_integration_tests")]
#[path = "integration_tests"]
mod integration_tests {
    #[cfg(test)]
    mod container_attrs;
    #[cfg(test)]
    mod field_attrs;
    #[cfg(test)]
    mod variant_attrs;
}
