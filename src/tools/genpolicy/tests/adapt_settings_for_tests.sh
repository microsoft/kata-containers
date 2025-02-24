#!/bin/sh
#
# Copyright (c) 2025 Microsoft Corporation
#
# SPDX-License-Identifier: Apache-2.0

# usage: ./tests/adapt_settings_for_tests.sh

jq '.request_defaults.CreateContainerRequest.allow_env_regex_map = {  
  "JOB_COMPLETION_INDEX": "^[0-9]*$",
  "CPU_LIMIT": "^[0-9]+$",
  "MEMORY_LIMIT": "^[0-9]+$"
}' genpolicy-settings.json > tmp-genpolicy-settings.json && mv tmp-genpolicy-settings.json genpolicy-settings.json