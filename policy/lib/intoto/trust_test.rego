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

package lib.intoto_test

import rego.v1

import data.lib.intoto

_image_ref := "registry.io/repo/image@sha256:abc123"

_statement_digest := "sha256:stmt000000000000000000000000000000000000000000000000000000000001"

_provenance_digest := "sha256:prov000000000000000000000000000000000000000000000000000000000001"

_statement_ref := sprintf("registry.io/repo/image@%s", [_statement_digest])

_provenance_ref := sprintf("registry.io/repo/image@%s", [_provenance_digest])

_bundle_ref := "quay.io/konflux-ci/tekton-catalog/task-verify@sha256:task00000000000000000000000000000000000000000000000000000000001"

_referrer(digest, artifact_type) := {
	"mediaType": "application/vnd.oci.image.manifest.v1+json",
	"size": 100,
	"digest": digest,
	"artifactType": artifact_type,
	"ref": sprintf("registry.io/repo/image@%s", [digest]),
}

_statement_referrer := _referrer(_statement_digest, "application/vnd.in-toto+json")

_provenance_referrer := _referrer(_provenance_digest, "application/vnd.dsse.envelope.v1+json")

_mock_blob(_) := json.marshal({
	"_type": "https://in-toto.io/Statement/v1",
	"predicateType": "https://in-toto.io/attestation/test-result/v0.1",
	"subject": [{"name": "registry.io/repo/image", "digest": {"sha256": "abc123"}}],
	"predicate": {"result": "PASSED"},
})

_mock_blob_vuln(_) := json.marshal({
	"_type": "https://in-toto.io/Statement/v1",
	"predicateType": "https://in-toto.io/attestation/vulns/v0.2",
	"subject": [{"name": "registry.io/repo/image", "digest": {"sha256": "abc123"}}],
	"predicate": {"scanner": {"uri": "https://scanner.example.com"}},
})

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

_slsa_v1_provenance(tasks) := {
	"statement": {
		"predicateType": "https://slsa.dev/provenance/v1",
		"predicate": {"buildDefinition": {
			"buildType": "https://tekton.dev/chains/v2/slsa-tekton",
			"resolvedDependencies": tasks,
		}},
	},
	"signatures": [{"keyid": "", "certificate": ""}],
}

_mock_verify_success(_, _) := {
	"success": true,
	"errors": [],
	"attestations": [_slsa_v1_provenance([_slsa_v1_task])],
}

_mock_verify_failure(_, _) := {
	"success": false,
	"errors": ["verification failed: no matching signatures"],
	"attestations": [],
}

_mock_verify_empty_attestations(_, _) := {
	"success": true,
	"errors": [],
	"attestations": [],
}

_mock_verify_empty_tasks(_, _) := {
	"success": true,
	"errors": [],
	"attestations": [_slsa_v1_provenance([])],
}

_mock_manifests(_) := {_bundle_ref: {"annotations": {"org.opencontainers.image.version": "1.0"}}}

_trusted_task_rules := {"trusted_task_rules": {"allow": {"Trusted tasks": [{"pattern": "oci://quay.io/konflux-ci/tekton-catalog/*"}]}}}

_mock_referrers_with_provenance(ref) := [_statement_referrer] if {
	ref == _image_ref
}

_mock_referrers_with_provenance(ref) := [_provenance_referrer] if {
	ref == _statement_ref
}

_mock_referrers_no_provenance(ref) := [_statement_referrer] if {
	ref == _image_ref
}

_mock_referrers_no_provenance(ref) := [] if {
	ref == _statement_ref
}

_statement_digest_2 := "sha256:stmt000000000000000000000000000000000000000000000000000000000002"

_statement_ref_2 := sprintf("registry.io/repo/image@%s", [_statement_digest_2])

_statement_referrer_2 := _referrer(_statement_digest_2, "application/vnd.in-toto+json")

_mock_referrers_multi(ref) := [_statement_referrer, _statement_referrer_2] if {
	ref == _image_ref
}

_mock_referrers_multi(ref) := [_provenance_referrer] if {
	ref == _statement_ref
}

_mock_referrers_multi(ref) := [] if {
	ref == _statement_ref_2
}

_mock_blob_multi(ref) := json.marshal({
	"_type": "https://in-toto.io/Statement/v1",
	"predicateType": "https://in-toto.io/attestation/test-result/v0.1",
	"subject": [{"name": "registry.io/repo/image", "digest": {"sha256": "abc123"}}],
	"predicate": {"result": "PASSED"},
}) if {
	contains(ref, "stmt000000000000000000000000000000000000000000000000000000000001")
}

_mock_blob_multi(ref) := json.marshal({
	"_type": "https://in-toto.io/Statement/v1",
	"predicateType": "https://in-toto.io/attestation/vulns/v0.2",
	"subject": [{"name": "registry.io/repo/image", "digest": {"sha256": "abc123"}}],
	"predicate": {"scanner": {"uri": "https://scanner.example.com"}},
}) if {
	contains(ref, "stmt000000000000000000000000000000000000000000000000000000000002")
}

_mock_referrers_both_verified(ref) := [_statement_referrer, _statement_referrer_2] if {
	ref == _image_ref
}

_mock_referrers_both_verified(ref) := [_provenance_referrer] if {
	ref == _statement_ref
}

_mock_referrers_both_verified(ref) := [_provenance_referrer] if {
	ref == _statement_ref_2
}

_slsa_v1_task_no_bundle := {
	"name": "pipelineTask",
	"content": base64.encode(json.marshal({
		"metadata": {"labels": {
			"tekton.dev/task": "inline-task",
			"tekton.dev/pipelineTask": "inline-task",
		}},
		"spec": {"params": []},
		"status": {
			"results": [{"name": "TEST_OUTPUT", "value": "{}"}],
			"steps": [{"name": "step1"}],
		},
	})),
}

_mock_verify_bundleless_tasks(_, _) := {
	"success": true,
	"errors": [],
	"attestations": [_slsa_v1_provenance([_slsa_v1_task_no_bundle])],
}

test_no_referrers if {
	result := intoto.verified_statements with input.image.ref as _image_ref
		with ec.oci.image_referrers as []

	count(result) == 0
}

test_verified_statement_happy_path if {
	result := intoto.verified_statements with input.image.ref as _image_ref
		with ec.oci.image_referrers as _mock_referrers_with_provenance
		with ec.sigstore.verify_attestation as _mock_verify_success
		with ec.oci.blob as _mock_blob
		with ec.oci.image_manifests as _mock_manifests
		with data.trusted_task_rules as _trusted_task_rules.trusted_task_rules

	count(result) == 1
	some statement in result
	statement.predicateType == "https://in-toto.io/attestation/test-result/v0.1"
	statement.predicate.result == "PASSED"
}

test_no_provenance_referrers if {
	result := intoto.verified_statements with input.image.ref as _image_ref
		with ec.oci.image_referrers as _mock_referrers_no_provenance
		with ec.oci.blob as _mock_blob

	count(result) == 0
}

test_invalid_signature if {
	result := intoto.verified_statements with input.image.ref as _image_ref
		with ec.oci.image_referrers as _mock_referrers_with_provenance
		with ec.sigstore.verify_attestation as _mock_verify_failure
		with ec.oci.blob as _mock_blob

	count(result) == 0
}

test_empty_attestations_after_verify if {
	result := intoto.verified_statements with input.image.ref as _image_ref
		with ec.oci.image_referrers as _mock_referrers_with_provenance
		with ec.sigstore.verify_attestation as _mock_verify_empty_attestations
		with ec.oci.blob as _mock_blob

	count(result) == 0
}

test_untrusted_tasks if {
	no_matching_rules := {"trusted_task_rules": {"allow": {"Other tasks": [{"pattern": "oci://quay.io/other-org/*"}]}}}
	result := intoto.verified_statements with input.image.ref as _image_ref
		with ec.oci.image_referrers as _mock_referrers_with_provenance
		with ec.sigstore.verify_attestation as _mock_verify_success
		with ec.oci.blob as _mock_blob
		with ec.oci.image_manifests as _mock_manifests
		with data.trusted_task_rules as no_matching_rules.trusted_task_rules

	count(result) == 0
}

test_denied_tasks if {
	deny_rules := {"trusted_task_rules": {
		"allow": {"Allow all": [{"pattern": "oci://quay.io/konflux-ci/tekton-catalog/*"}]},
		"deny": {"Block verify": [{"pattern": "oci://quay.io/konflux-ci/tekton-catalog/task-verify*"}]},
	}}
	result := intoto.verified_statements with input.image.ref as _image_ref
		with ec.oci.image_referrers as _mock_referrers_with_provenance
		with ec.sigstore.verify_attestation as _mock_verify_success
		with ec.oci.blob as _mock_blob
		with ec.oci.image_manifests as _mock_manifests
		with data.trusted_task_rules as deny_rules.trusted_task_rules

	count(result) == 0
}

test_empty_tasks_vacuous_truth_guard if {
	result := intoto.verified_statements with input.image.ref as _image_ref
		with ec.oci.image_referrers as _mock_referrers_with_provenance
		with ec.sigstore.verify_attestation as _mock_verify_empty_tasks
		with ec.oci.blob as _mock_blob
		with ec.oci.image_manifests as _mock_manifests
		with data.trusted_task_rules as _trusted_task_rules.trusted_task_rules

	count(result) == 0
}

test_bundleless_tasks if {
	result := intoto.verified_statements with input.image.ref as _image_ref
		with ec.oci.image_referrers as _mock_referrers_with_provenance
		with ec.sigstore.verify_attestation as _mock_verify_bundleless_tasks
		with ec.oci.blob as _mock_blob
		with ec.oci.image_manifests as _mock_manifests
		with data.trusted_task_rules as _trusted_task_rules.trusted_task_rules

	count(result) == 0
}

test_multiple_statements_mixed if {
	result := intoto.verified_statements with input.image.ref as _image_ref
		with ec.oci.image_referrers as _mock_referrers_multi
		with ec.sigstore.verify_attestation as _mock_verify_success
		with ec.oci.blob as _mock_blob_multi
		with ec.oci.image_manifests as _mock_manifests
		with data.trusted_task_rules as _trusted_task_rules.trusted_task_rules

	count(result) == 1
	some statement in result
	statement.predicateType == "https://in-toto.io/attestation/test-result/v0.1"
}

test_verified_statements_by_predicate if {
	result := intoto.verified_statements_by_predicate(intoto.predicate_test_result) with input.image.ref as _image_ref
		with ec.oci.image_referrers as _mock_referrers_both_verified
		with ec.sigstore.verify_attestation as _mock_verify_success
		with ec.oci.blob as _mock_blob_multi
		with ec.oci.image_manifests as _mock_manifests
		with data.trusted_task_rules as _trusted_task_rules.trusted_task_rules

	count(result) == 1
	some statement in result
	statement.predicateType == "https://in-toto.io/attestation/test-result/v0.1"
}
