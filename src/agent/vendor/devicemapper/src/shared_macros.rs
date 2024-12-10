// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// A module to contain functionality shared among the various types of
// devices and implemented by means of macros.

macro_rules! device {
    ($s:ident) => {
        $s.dev_info.device()
    };
}

macro_rules! name {
    ($s:ident) => {
        match $s.dev_info.name() {
            Some(n) => n,
            None => panic!("Name is required for device"),
        }
    };
}

macro_rules! uuid {
    ($s:ident) => {
        $s.dev_info.uuid()
    };
}

macro_rules! devnode {
    ($s:ident) => {
        ["/dev", &format!("dm-{}", $s.dev_info.device().minor)]
            .iter()
            .collect()
    };
}

macro_rules! to_raw_table_unique {
    ($s:ident) => {
        vec![(
            *$s.table.start,
            *$s.table.length,
            $s.table.params.target_type().to_string(),
            $s.table.params.param_str(),
        )]
    };
}

macro_rules! table {
    ($s:ident) => {
        &$s.table
    };
}

macro_rules! status {
    ($s:ident, $dm:ident, $options:ident) => {
        get_status(
            &$dm.table_status(&$crate::core::DevId::Name($s.name()), $options)?
                .1,
        )?
        .parse()
    };
}
