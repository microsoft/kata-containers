use std::env::temp_dir;
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{anyhow, Result};
use rand::{distributions::Alphanumeric, Rng};
use slog::Logger;
use tracing::instrument;

// encrypt_device encrypts and formats a device, then returns the path
// of the newly-created dm-crypt device.
#[instrument]
pub fn encrypt_device(logger: &Logger, device_path: &Path) -> Result<PathBuf> {
    // Path to the key file that will be passed to the cryptsetup
    // commands.
    let key_file_path = {
        let random_string: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(5)
            .map(char::from)
            .collect();
        let filename = format!("encrypted_storage_key_{}", random_string);
        temp_dir().join(filename)
    };

    // Generate a random encryption key and write it to the key file.
    let mut key = vec![0u8; 4096];
    rand::thread_rng().fill(&mut key[..]);
    let mut key_file = File::create(&key_file_path)?;
    key_file.write_all(&key)?;

    // Name of the devmapper that will live under /dev/mapper/.
    let devmapper_device_name = device_path
        .file_name()
        .ok_or_else(|| anyhow!("invalid path"))?
        .to_string_lossy()
        .into_owned();

    let script_path: PathBuf = temp_dir().join("luks-encrypt-storage.sh");
    if !script_path.exists() {
        let mut script_file = File::create(&script_path)?;
        script_file.write_all(LUKS_ENCRYPT_STORAGE_SCRIPT.as_bytes())?;
    }

    info!(logger, "Running luks-encrypt-storage.sh");
    let output = Command::new("bash")
        .args([
            script_path.display().to_string(),
            device_path.display().to_string(),   // device_path
            devmapper_device_name.to_string(),   // opened_device_name
            "false".to_string(),                 // is_encrypted (false so the script encrypts it)
            key_file_path.display().to_string(), // storage_key_path
            "true".to_string(),                  // data_integrity
        ])
        .output()?;
    if !output.status.success() {
        info!(logger, "Failed to run luks-encrypt-storage.sh";
            "status" => output.status.code().unwrap_or(-1),
            "stdout" => String::from_utf8_lossy(&output.stdout).to_string(),
            "stderr" => String::from_utf8_lossy(&output.stderr).to_string(),
        );
        assert!(output.status.success());
    }

    // We're now mounting from the dm-crypt device, not the original
    // device (now ciphertext), so we return the devmapper device.
    let devmapper_device_path = PathBuf::from(format!("/dev/mapper/{devmapper_device_name}"));
    Ok(devmapper_device_path)
}

// Reference: https://github.com/confidential-containers/guest-components/blob/main/confidential-data-hub/storage/scripts/luks-encrypt-storage
static LUKS_ENCRYPT_STORAGE_SCRIPT: &str = r#"
#!/bin/bash
#
# Copyright (c) 2022 Intel Corporation
#
# SPDX-License-Identifier: Apache-2.0
#

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace

#[ -n "${DEBUG:-}" ] && set -o xtrace
set -o xtrace

handle_error() {
        local exit_code="${?}"
        local line_number="${1:-}"
        echo "error:"
        echo "Failed at $line_number: ${BASH_COMMAND}"
        exit "${exit_code}"
}
trap 'handle_error $LINENO' ERR

die()
{
	local msg="$*"
	echo >&2 "ERROR: $msg"
	exit 1
}

setup()
{
	local cmds=()

	cmds+=("cryptsetup" "mkfs.ext4" "mount")

	local cmd
	for cmd in "${cmds[@]}"
	do
		command -v "$cmd" &>/dev/null || die "need command: '$cmd'"
	done
}

setup

device_path=${1:-}
if [ -z "$device_path" ]; then
	die "invalid arguments, at least one param for device path"
fi

opened_device_name=${2:-}
if [ -z "$opened_device_name" ]; then
	die "invalid arguments, at least one param for device path"
fi

is_encrypted="false"
if [ -n "${3-}" ]; then
        is_encrypted="$3"
fi

storage_key_path="/run/encrypt_storage.key"
if [ -n "${4-}" ]; then
        storage_key_path="$4"
fi

data_integrity="true"
if [ -n "${5-}" ]; then
        data_integrity="$5"
fi

if [[ -b "$device_path" ]]; then

	if [ "$is_encrypted" == "false" ]; then
        echo >&2  "is_encrypted=false branch"

		if [ "$data_integrity" == "false" ]; then
            echo >&2  "integ=false branch"
			cryptsetup --verbose --debug --batch-mode luksFormat --type luks2 "$device_path" --sector-size 4096 \
				--cipher aes-xts-plain64 "$storage_key_path"
		else
            echo >&2  "integ=true branch"
				# Wiping a device is a time consuming operation. To avoid a full wipe, integritysetup
				# and crypt setup provide a --no-wipe option.
				# However, an integrity device that is not wiped will have invalid checksums. Normally
				# this should not be a problem since a page must first be written to before it can be read
				# (otherwise the data would be arbitrary). The act of writing would populate the checksum
				# for the page.
				# However, tools like mkfs.ext4 read pages before they are written; sometimes the read
				# of an unwritten page happens due to kernel buffering.
				# See https://gitlab.com/cryptsetup/cryptsetup/-/issues/525 for explanation and fix.
				# The way to propery format the non-wiped dm-integrity device is to figure out which pages
				# mkfs.ext4 will write to and then to write to those pages before hand so that they will
				# have valid integrity tags.
			cryptsetup --verbose --debug --batch-mode luksFormat --type luks2 "$device_path" --sector-size 4096 \
				--cipher aes-xts-plain64 --integrity hmac-sha256 "$storage_key_path" \
				--integrity-no-wipe
		fi
	fi

	cryptsetup luksOpen -d "$storage_key_path" "$device_path" "$opened_device_name"
	rm "$storage_key_path"

	if [ "$data_integrity" == "false" ]; then
		mkfs.ext4 "/dev/mapper/$opened_device_name" -E lazy_journal_init
	else
		# mkfs.ext4 doesn't perform whole sector writes and this will cause checksum failures
		# with an unwiped integrity device. Therefore, first perform a dry run.
		output=$(mkfs.ext4 "/dev/mapper/$opened_device_name" -F -n)

		# The above command will produce output like
		# mke2fs 1.46.5 (30-Dec-2021)
		# Creating filesystem with 268435456 4k blocks and 67108864 inodes
		# Filesystem UUID: 4a5ff012-91c0-47d9-b4bb-8f83e830825f
		# Superblock backups stored on blocks:
		#         32768, 98304, 163840, 229376, 294912, 819200, 884736, 1605632, 2654208,
		#         4096000, 7962624, 11239424, 20480000, 23887872, 71663616, 78675968,
		#         102400000, 214990848
		delimiter="Superblock backups stored on blocks:"
		blocks_list=$([[ $output =~ $delimiter(.*) ]] && echo "${BASH_REMATCH[1]}")

		# Find list of blocks
		block_nums=$(echo  "$blocks_list" | grep -Eo '[0-9]{4,}' | sort -n)

		if [ -z "$block_nums" ]; then
			die "Block numbers not found"
		fi

		# Add zero to list of blocks
		block_nums="0 $block_nums"

		# Iterate through each block and write to it to ensure that it has valid checksum
		for block_num in $block_nums
		do
		echo "Clearing page at $block_num"
		# Zero out the page
		dd if=/dev/zero bs=4k count=1 oflag=direct \
		of="/dev/mapper/$opened_device_name" seek="$block_num"
		done

		# Now perform the actual ext4 format. Use lazy_journal_init so that the journal is
		# initialized on demand. This is safe for ephemeral storage since we don't expect
		# ephemeral storage to survice a power cycle.
		mkfs.ext4 "/dev/mapper/$opened_device_name" -E lazy_journal_init
	fi
else
	die "Invalid device: '$device_path'"
fi
"#;
