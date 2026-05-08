# Copyright The Conforma Contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

# Chain-of-trust verification for in-toto statements.
#
# This file deliberately couples lib.intoto with lib.sigstore, lib.tekton,
# and ec.oci/ec.sigstore built-ins to verify that in-toto statements were
# produced by trusted pipelines. If the intoto package grows beyond 3-4
# files, consider extracting trust verification into a dedicated package.
#
# Cross-file dependency: this file references _artifact_type and
# _known_types defined in intoto.rego (same package).
#
# Trust model: "one valid provenance chain suffices." A statement is
# verified if ANY second-level referrer provides valid Chains-generated
# SLSA provenance with all tasks trusted. Not all referrers must verify.
#
# Fail-closed behavior: if blob fetching, JSON parsing, or _type
# validation fails for a referrer, that statement is silently excluded
# from verified_statements. Consumer deny rules surface the absence.

package lib.intoto

import rego.v1

# import data.lib.sigstore  -- added in EC-1774 Task 3 when verified_statements is implemented
# import data.lib.tekton     -- added in EC-1774 Task 3 when verified_statements is implemented

_intoto_referrers contains referrer if {
	some referrer in ec.oci.image_referrers(input.image.ref)
	referrer.artifactType == _artifact_type
}

verified_statements := set()
