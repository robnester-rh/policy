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

package test_attestation_test

import rego.v1

import data.lib.assertions
import data.test_attestation

_image_ref := "registry.io/repo/image@sha256:abc123"

_statement_digest := "sha256:stmt000000000000000000000000000000000000000000000000000000000001"

_provenance_digest := "sha256:prov000000000000000000000000000000000000000000000000000000000001"

_statement_ref := sprintf("registry.io/repo/image@%s", [_statement_digest])

_bundle_ref := "quay.io/konflux-ci/tekton-catalog/task-verify@sha256:task00000000000000000000000000000000000000000000000000000000001"

_trusted_task_rules := {"trusted_task_rules": {"allow": {"Trusted tasks": [{"pattern": "oci://quay.io/konflux-ci/tekton-catalog/*"}]}}}

_referrer(digest, artifact_type) := {
	"mediaType": "application/vnd.oci.image.manifest.v1+json",
	"size": 100,
	"digest": digest,
	"artifactType": artifact_type,
	"ref": sprintf("registry.io/repo/image@%s", [digest]),
}

_statement_referrer := _referrer(_statement_digest, "application/vnd.in-toto+json")

_provenance_referrer := _referrer(_provenance_digest, "application/vnd.dsse.envelope.v1+json")

_mock_referrers(ref) := [_statement_referrer] if {
	ref == _image_ref
}

_mock_referrers(ref) := [_provenance_referrer] if {
	ref == _statement_ref
}

_slsa_v1_task := {
	"name": "pipelineTask",
	"content": base64.encode(json.marshal({
		"metadata": {"labels": {
			"tekton.dev/task": "verify-task",
			"tekton.dev/pipelineTask": "verify-task",
		}},
		"spec": {
			"params": [],
			"taskRef": {
				"resolver": "bundles",
				"params": [
					{"name": "name", "value": "verify-task"},
					{"name": "bundle", "value": _bundle_ref},
					{"name": "kind", "value": "task"},
				],
			},
		},
		"status": {
			"results": [{"name": "TEST_OUTPUT", "value": "{}"}],
			"steps": [{"name": "step1"}],
		},
	})),
}

_parse_digest(digest_str) := {algorithm: value} if {
	parts := split(digest_str, ":")
	algorithm := parts[0]
	value := parts[1]
}

_slsa_v1_provenance := {
	"statement": {
		"predicateType": "https://slsa.dev/provenance/v1",
		"subject": [{"name": "statement", "digest": _parse_digest(_statement_digest)}],
		"predicate": {"buildDefinition": {
			"buildType": "https://tekton.dev/chains/v2/slsa-tekton",
			"resolvedDependencies": [_slsa_v1_task],
		}},
	},
	"signatures": [{"keyid": "", "certificate": ""}],
}

_mock_verify_success(_, _) := {
	"success": true,
	"errors": [],
	"attestations": [_slsa_v1_provenance],
}

_mock_manifests(_) := {_bundle_ref: {"annotations": {"org.opencontainers.image.version": "1.0"}}}

_make_statement(predicate) := json.marshal({
	"_type": "https://in-toto.io/Statement/v1",
	"predicateType": "https://in-toto.io/attestation/test-result/v0.1",
	"subject": [{"name": "registry.io/repo/image", "digest": {"sha256": "abc123"}}],
	"predicate": predicate,
})

# Package-level mock blob functions for each test scenario

_mock_blob_passed(_) := _make_statement({
	"result": "PASSED",
	"configuration": [{"name": "clair-scan"}],
	"passedTests": ["test-a", "test-b"],
})

_mock_blob_failed_with_details(_) := _make_statement({
	"result": "FAILED",
	"configuration": [{"name": "clair-scan"}],
	"failedTests": ["CVE-2024-1234", "CVE-2024-5678"],
})

_mock_blob_failed_no_details(_) := _make_statement({
	"result": "FAILED",
	"configuration": [{"name": "sanity-check"}],
})

_mock_blob_warned(_) := _make_statement({
	"result": "WARNED",
	"configuration": [{"name": "deprecation-check"}],
	"warnedTests": ["deprecated-api-v1"],
})

_mock_blob_unknown_result(_) := _make_statement({
	"result": "ERROR",
	"configuration": [{"name": "lint-check"}],
})

_mock_blob_missing_result(_) := _make_statement({
	"configuration": [{"name": "incomplete-test"}],
	"passedTests": ["test-a"],
})

# --- Test Case 1: All attestations PASSED ---

test_all_passed_no_violations if {
	assertions.assert_empty(test_attestation.deny) with input.image.ref as _image_ref
		with ec.oci.image_referrers as _mock_referrers
		with ec.sigstore.verify_attestation as _mock_verify_success
		with ec.oci.blob as _mock_blob_passed
		with ec.oci.image_manifests as _mock_manifests
		with data.trusted_task_rules as _trusted_task_rules.trusted_task_rules

	assertions.assert_empty(test_attestation.warn) with input.image.ref as _image_ref
		with ec.oci.image_referrers as _mock_referrers
		with ec.sigstore.verify_attestation as _mock_verify_success
		with ec.oci.blob as _mock_blob_passed
		with ec.oci.image_manifests as _mock_manifests
		with data.trusted_task_rules as _trusted_task_rules.trusted_task_rules
}

# --- Test Case 2: FAILED with failedTests array ---

test_failed_with_details if {
	assertions.assert_equal_results(test_attestation.deny, {{
		"code": "test_attestation.no_failed_tests",
		"msg": "Test attestation \"clair-scan\" reports a failed result. Failed tests: CVE-2024-1234, CVE-2024-5678",
		"term": "clair-scan",
	}}) with input.image.ref as _image_ref
		with ec.oci.image_referrers as _mock_referrers
		with ec.sigstore.verify_attestation as _mock_verify_success
		with ec.oci.blob as _mock_blob_failed_with_details
		with ec.oci.image_manifests as _mock_manifests
		with data.trusted_task_rules as _trusted_task_rules.trusted_task_rules
}

# --- Test Case 3: FAILED without failedTests array ---

test_failed_no_details if {
	assertions.assert_equal_results(test_attestation.deny, {{
		"code": "test_attestation.no_failed_tests",
		"msg": "Test attestation \"sanity-check\" reports a failed result. Failed tests: (none listed)",
		"term": "sanity-check",
	}}) with input.image.ref as _image_ref
		with ec.oci.image_referrers as _mock_referrers
		with ec.sigstore.verify_attestation as _mock_verify_success
		with ec.oci.blob as _mock_blob_failed_no_details
		with ec.oci.image_manifests as _mock_manifests
		with data.trusted_task_rules as _trusted_task_rules.trusted_task_rules
}

# --- Test Case 4: WARNED with warnedTests array ---

test_warned_with_details if {
	assertions.assert_empty(test_attestation.deny) with input.image.ref as _image_ref
		with ec.oci.image_referrers as _mock_referrers
		with ec.sigstore.verify_attestation as _mock_verify_success
		with ec.oci.blob as _mock_blob_warned
		with ec.oci.image_manifests as _mock_manifests
		with data.trusted_task_rules as _trusted_task_rules.trusted_task_rules

	assertions.assert_equal_results(test_attestation.warn, {{
		"code": "test_attestation.no_test_warnings",
		"msg": "Test attestation \"deprecation-check\" reports warnings. Warned tests: deprecated-api-v1",
		"term": "deprecation-check",
	}}) with input.image.ref as _image_ref
		with ec.oci.image_referrers as _mock_referrers
		with ec.sigstore.verify_attestation as _mock_verify_success
		with ec.oci.blob as _mock_blob_warned
		with ec.oci.image_manifests as _mock_manifests
		with data.trusted_task_rules as _trusted_task_rules.trusted_task_rules
}

# --- Test Case 6: Unknown result value ---

test_unknown_result_value if {
	assertions.assert_equal_results(test_attestation.deny, {{
		"code": "test_attestation.test_result_known",
		"msg": "Test attestation \"lint-check\" has an unsupported result value \"ERROR\"",
		"term": "lint-check",
	}}) with input.image.ref as _image_ref
		with ec.oci.image_referrers as _mock_referrers
		with ec.sigstore.verify_attestation as _mock_verify_success
		with ec.oci.blob as _mock_blob_unknown_result
		with ec.oci.image_manifests as _mock_manifests
		with data.trusted_task_rules as _trusted_task_rules.trusted_task_rules
}

# --- Test Case 7: Missing result field ---

test_missing_result_field if {
	assertions.assert_equal_results(test_attestation.deny, {{
		"code": "test_attestation.test_data_found",
		"msg": "Test attestation \"incomplete-test\" is missing the required result field",
		"term": "incomplete-test",
	}}) with input.image.ref as _image_ref
		with ec.oci.image_referrers as _mock_referrers
		with ec.sigstore.verify_attestation as _mock_verify_success
		with ec.oci.blob as _mock_blob_missing_result
		with ec.oci.image_manifests as _mock_manifests
		with data.trusted_task_rules as _trusted_task_rules.trusted_task_rules
}
