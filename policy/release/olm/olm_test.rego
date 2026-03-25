package olm_test

import rego.v1

import data.lib.assertions
import data.lib.metadata
import data.lib.tekton_test
import data.lib_test
import data.olm

unpinned := "registry.io/repo/msd:no_digest"

unpinned_related_img := "registry.io/repo/msd:latest"

pinned0 := "registry.io/repository/image@sha256:dosa"

pinned1 := "registry.io/repository/image@sha256:cafe"

pinned2 := "registry.io/repository/image2@sha256:tea"

pinned3 := "registry.io/repository/image3@sha256:coffee"

pinned_ref := {"digest": "sha256:cafe", "repo": "registry.io/repository/image", "tag": ""}

pinned_ref2 := {"digest": "sha256:tea", "repo": "registry.io/repository/image2", "tag": ""}

component0 := {
	"name": "Unnamed",
	"containerImage": pinned0,
	"source": {},
}

component1 := {
	"name": "Unnamed",
	"containerImage": pinned1,
	"source": {},
}

component2 := {
	"name": "pinned_image2",
	"containerImage": pinned2,
	"source": {},
}

component3 := {
	"name": "pinned_image3",
	"containerImage": pinned3,
	"source": {},
}

unpinned_component := {
	"name": "unpinned_image",
	"containerImage": unpinned,
	"source": {},
}

manifest := {
	"apiVersion": "operators.coreos.com/v1alpha1",
	"kind": "ClusterServiceVersion",
	"metadata": {"annotations": {
		"containerImage": pinned1,
		"enclosurePicture": sprintf("%s,  %s", [pinned1, pinned2]),
		"features.operators.openshift.io/disconnected": "true",
		"features.operators.openshift.io/fips-compliant": "true",
		"features.operators.openshift.io/proxy-aware": "true",
		"features.operators.openshift.io/tls-profiles": "false",
		"features.operators.openshift.io/token-auth-aws": "false",
		"features.operators.openshift.io/token-auth-azure": "false",
		"features.operators.openshift.io/token-auth-gcp": "false",
		"operators.openshift.io/valid-subscription": `["spam"]`,
		"alm-examples": `"endpoint": "http://example:4317" spam`,
		# regal ignore:line-length
		"features.operators.image": `{"kind":"Namespace","apiVersion":"v1","metadata":{"name":"openshift-workload-availability","annotations":{"openshift.io/node-selector":""}}}`,
	}},
	"spec": {
		"version": "0.1.3",
		"relatedImages": [{"image": pinned1}],
		"install": {"spec": {"deployments": [{
			"metadata": {"annotations": {"docket": sprintf("%s\n  %s", [pinned1, pinned2])}},
			"spec": {"template": {
				"metadata": {"name": "c1"},
				"spec": {
					"containers": [{
						"name": "c1",
						"image": pinned1,
						"env": [{"name": "RELATED_IMAGE_C1", "value": pinned1}],
					}],
					"initContainers": [{
						"name": "i1",
						"image": pinned1,
						"env": [{"name": "RELATED_IMAGE_E1", "value": pinned1}],
					}],
				},
			}},
		}]}},
	},
	"not-metadata": {"annotations": {"something": pinned2}},
	"metadata-without-annotations": {"metadata": {}},
	"metadata-with-empty-annotations": {"metadata": {"annotations": {}}},
}

network_policy_manifest := {
	"apiVersion": "networking.k8s.io/v1",
	"kind": "NetworkPolicy",
	"metadata": {"name": "default-deny"},
	"spec": {"podSelector": {}, "policyTypes": ["Ingress", "Egress"]},
}

service_manifest := {
	"apiVersion": "v1",
	"kind": "Service",
	"metadata": {"name": "simple-demo-operator-controller-manager-metrics-service"},
	"spec": {"ports": [{"port": 8443, "targetPort": 8443}]},
}

# regal ignore:rule-length
test_all_image_ref if {
	assertions.assert_equal(
		[
			{"path": "spec.relatedImages[0].image", "ref": pinned_ref},
			{"path": "annotations.containerImage", "ref": pinned_ref},
			{"path": "annotations[\"containerImage\"]", "ref": pinned_ref},
			{"path": "annotations[\"enclosurePicture\"]", "ref": pinned_ref},
			{"path": "annotations[\"enclosurePicture\"]", "ref": pinned_ref2},
			{"path": "annotations[\"docket\"]", "ref": pinned_ref},
			{"path": "annotations[\"docket\"]", "ref": pinned_ref2},
			{
				"path": `spec.install.spec.deployments[0 ("unnamed")].spec.template.spec.containers[0 ("c1")].image`,
				"ref": pinned_ref,
			},
			{
				# regal ignore:line-length
				"path": `spec.install.spec.deployments[0 ("unnamed")].spec.template.spec.initContainers[0 ("i1")].image`,
				"ref": pinned_ref,
			},
			{
				# regal ignore:line-length
				"path": `spec.install.spec.deployments[0 ("unnamed")].spec.template.spec.containers[0 ("c1")].env["RELATED_IMAGE_C1"]`,
				"ref": pinned_ref,
			},
			{
				# regal ignore:line-length
				"path": `spec.install.spec.deployments[0 ("unnamed")].spec.template.spec.initContainers[0 ("i1")].env["RELATED_IMAGE_E1"]`,
				"ref": pinned_ref,
			},
		],
		olm.all_image_ref(manifest),
	)
}

test_all_good if {
	assertions.assert_empty(olm.deny) with input.image.files as {"manifests/csv.yaml": manifest}
		with input.image.config.Labels as {olm.manifestv1: "manifests/"}
		with data.rule_data.allowed_olm_image_registry_prefixes as ["registry.io"]
		with data.rule_data.allowed_olm_resource_kinds as ["ClusterServiceVersion"]
}

test_all_good_custom_dir if {
	assertions.assert_empty(olm.deny) with input.image.files as {"other/csv.yaml": manifest}
		with input.image.config.Labels as {olm.manifestv1: "other/"}
		with data.rule_data.allowed_olm_image_registry_prefixes as ["registry.io"]
		with data.rule_data.allowed_olm_resource_kinds as ["ClusterServiceVersion"]
}

test_related_img_unpinned if {
	unpinned_manifest = json.patch(manifest, [{
		"op": "replace",
		"path": "/spec/install/spec/deployments/0/spec/template/spec/containers/0/env/0/value",
		"value": "registry.io/repository:tag",
	}])

	expected = {{
		"code": "olm.unpinned_references",
		# regal ignore:line-length
		"msg": `The "registry.io/repository:tag" image reference is not pinned at spec.install.spec.deployments[0 ("unnamed")].spec.template.spec.containers[0 ("c1")].env["RELATED_IMAGE_C1"].`,
		"term": "registry.io/repository:tag",
	}}

	assertions.assert_equal_results(olm.deny, expected) with input.image.files as {"manifests/csv.yaml": unpinned_manifest}
		with input.image.config.Labels as {olm.manifestv1: "manifests/"}
		with data.rule_data.allowed_olm_image_registry_prefixes as ["registry.io"]
		with data.rule_data.allowed_olm_resource_kinds as ["ClusterServiceVersion"]
}

test_feature_annotations_format if {
	bad_manifest := json.patch(manifest, [
		{"op": "add", "path": "/metadata/annotations/features.operators.openshift.io~1disconnected", "value": false},
		{"op": "add", "path": "/metadata/annotations/features.operators.openshift.io~1fips-compliant", "value": true},
		{"op": "add", "path": "/metadata/annotations/features.operators.openshift.io~1proxy-aware", "value": 1},
		{"op": "remove", "path": "/metadata/annotations/features.operators.openshift.io~1tls-profiles"},
	])

	expected := {
		{
			"code": "olm.feature_annotations_format",
			# regal ignore:line-length
			"msg": "The annotation \"features.operators.openshift.io/disconnected\" is either missing or has an unexpected value",
			"term": "features.operators.openshift.io/disconnected",
		},
		{
			"code": "olm.feature_annotations_format",
			# regal ignore:line-length
			"msg": "The annotation \"features.operators.openshift.io/fips-compliant\" is either missing or has an unexpected value",
			"term": "features.operators.openshift.io/fips-compliant",
		},
		{
			"code": "olm.feature_annotations_format",
			"msg": "The annotation \"features.operators.openshift.io/proxy-aware\" is either missing or has an unexpected value",
			"term": "features.operators.openshift.io/proxy-aware",
		},
		{
			"code": "olm.feature_annotations_format",
			# regal ignore:line-length
			"msg": "The annotation \"features.operators.openshift.io/tls-profiles\" is either missing or has an unexpected value",
			"term": "features.operators.openshift.io/tls-profiles",
		},
	}

	assertions.assert_equal_results(olm.deny, expected) with input.image.files as {"manifests/csv.yaml": bad_manifest}
		with input.image.config.Labels as {olm.manifestv1: "manifests/"}
		with data.rule_data.allowed_olm_image_registry_prefixes as ["registry.io"]
		with data.rule_data.allowed_olm_resource_kinds as ["ClusterServiceVersion"]
}

test_feature_annotations_format_custom_rule_data if {
	bad_manifest := json.patch(manifest, [
		{"op": "add", "path": "/metadata/annotations/foo", "value": "bar"},
		{"op": "add", "path": "/metadata/annotations/spam", "value": "true"},
	])

	expected := {{
		"code": "olm.feature_annotations_format",
		"msg": "The annotation \"foo\" is either missing or has an unexpected value", "term": "foo",
	}}

	assertions.assert_equal_results(olm.deny, expected) with input.image.files as {"manifests/csv.yaml": bad_manifest}
		with input.image.config.Labels as {olm.manifestv1: "manifests/"}
		with data.rule_data.required_olm_features_annotations as ["foo", "spam"]
		with data.rule_data.allowed_olm_image_registry_prefixes as ["registry.io"]
		with data.rule_data.allowed_olm_resource_kinds as ["ClusterServiceVersion"]
}

# Test: Bundle created before FIPS cutoff date is exempt from FIPS check
test_fips_exempt_for_legacy_bundle if {
	# Remove FIPS annotation but add createdAt before the cutoff date
	legacy_manifest := json.patch(manifest, [
		{"op": "remove", "path": "/metadata/annotations/features.operators.openshift.io~1fips-compliant"},
		{"op": "add", "path": "/metadata/annotations/createdAt", "value": "2025-01-15T00:00:00Z"},
	])

	# Should NOT have FIPS annotation violation (exempt due to creation date before cutoff)
	assertions.assert_empty(olm.deny) with input.image.files as {"manifests/csv.yaml": legacy_manifest}
		with input.image.config.Labels as {olm.manifestv1: "manifests/"}
		with data.rule_data.allowed_olm_image_registry_prefixes as ["registry.io"]
		with data.rule_data.allowed_olm_resource_kinds as ["ClusterServiceVersion"]
		with data.rule_data.fips_exempt_created_before as "2025-01-31T00:00:00Z"
}

# Test: FIPS exemption works with default cutoff date from rule_data.rego
test_fips_exempt_uses_default_cutoff if {
	# Remove FIPS annotation but add createdAt before the default cutoff (2025-01-31T00:00:00Z)
	legacy_manifest := json.patch(manifest, [
		{"op": "remove", "path": "/metadata/annotations/features.operators.openshift.io~1fips-compliant"},
		{"op": "add", "path": "/metadata/annotations/createdAt", "value": "2025-01-15T00:00:00Z"},
	])

	# Should be exempt using the default cutoff date from rule_data.rego
	# (not explicitly setting fips_exempt_created_before)
	assertions.assert_empty(olm.deny) with input.image.files as {"manifests/csv.yaml": legacy_manifest}
		with input.image.config.Labels as {olm.manifestv1: "manifests/"}
		with data.rule_data.allowed_olm_image_registry_prefixes as ["registry.io"]
		with data.rule_data.allowed_olm_resource_kinds as ["ClusterServiceVersion"]
}

# Test: Bundle created after FIPS cutoff date is NOT exempt from FIPS check
test_fips_not_exempt_for_new_bundle if {
	# Remove FIPS annotation but add createdAt after the cutoff date
	new_manifest := json.patch(manifest, [
		{"op": "remove", "path": "/metadata/annotations/features.operators.openshift.io~1fips-compliant"},
		{"op": "add", "path": "/metadata/annotations/createdAt", "value": "2025-02-15T00:00:00Z"},
	])

	expected := {{
		"code": "olm.feature_annotations_format",
		# regal ignore:line-length
		"msg": "The annotation \"features.operators.openshift.io/fips-compliant\" is either missing or has an unexpected value",
		"term": "features.operators.openshift.io/fips-compliant",
	}}

	assertions.assert_equal_results(olm.deny, expected) with input.image.files as {"manifests/csv.yaml": new_manifest}
		with input.image.config.Labels as {olm.manifestv1: "manifests/"}
		with data.rule_data.allowed_olm_image_registry_prefixes as ["registry.io"]
		with data.rule_data.allowed_olm_resource_kinds as ["ClusterServiceVersion"]
		with data.rule_data.fips_exempt_created_before as "2025-01-31T00:00:00Z"
}

# Test: Bundle without createdAt annotation is NOT exempt from FIPS check
test_fips_not_exempt_without_created_at if {
	# Remove FIPS annotation without adding createdAt
	# regal ignore:line-length
	no_date_manifest := json.patch(manifest, [{"op": "remove", "path": "/metadata/annotations/features.operators.openshift.io~1fips-compliant"}])

	expected := {{
		"code": "olm.feature_annotations_format",
		# regal ignore:line-length
		"msg": "The annotation \"features.operators.openshift.io/fips-compliant\" is either missing or has an unexpected value",
		"term": "features.operators.openshift.io/fips-compliant",
	}}

	assertions.assert_equal_results(olm.deny, expected) with input.image.files as {"manifests/csv.yaml": no_date_manifest}
		with input.image.config.Labels as {olm.manifestv1: "manifests/"}
		with data.rule_data.allowed_olm_image_registry_prefixes as ["registry.io"]
		with data.rule_data.allowed_olm_resource_kinds as ["ClusterServiceVersion"]
		with data.rule_data.fips_exempt_created_before as "2025-01-31T00:00:00Z"
}

# Test: Only FIPS annotation is exempt for legacy bundles; other annotations still checked
test_fips_exempt_other_annotations_still_checked if {
	# Remove both FIPS and another annotation, with old creation date
	multi_missing_manifest := json.patch(manifest, [
		{"op": "remove", "path": "/metadata/annotations/features.operators.openshift.io~1fips-compliant"},
		{"op": "remove", "path": "/metadata/annotations/features.operators.openshift.io~1disconnected"},
		{"op": "add", "path": "/metadata/annotations/createdAt", "value": "2024-06-15T00:00:00Z"},
	])

	# FIPS should be exempt, but disconnected should still be checked
	expected := {{
		"code": "olm.feature_annotations_format",
		# regal ignore:line-length
		"msg": "The annotation \"features.operators.openshift.io/disconnected\" is either missing or has an unexpected value",
		"term": "features.operators.openshift.io/disconnected",
	}}

	assertions.assert_equal_results(olm.deny, expected) with input.image.files as {"manifests/csv.yaml": multi_missing_manifest}
		with input.image.config.Labels as {olm.manifestv1: "manifests/"}
		with data.rule_data.allowed_olm_image_registry_prefixes as ["registry.io"]
		with data.rule_data.allowed_olm_resource_kinds as ["ClusterServiceVersion"]
		with data.rule_data.fips_exempt_created_before as "2025-01-31T00:00:00Z"
}

# Test: Bundle created exactly on cutoff date is NOT exempt
test_fips_not_exempt_on_cutoff_date if {
	# Create bundle with createdAt exactly on the cutoff date
	on_cutoff_manifest := json.patch(manifest, [
		{"op": "remove", "path": "/metadata/annotations/features.operators.openshift.io~1fips-compliant"},
		{"op": "add", "path": "/metadata/annotations/createdAt", "value": "2025-01-31T00:00:00Z"},
	])

	# Should NOT be exempt because it's not strictly before the cutoff
	expected := {{
		"code": "olm.feature_annotations_format",
		# regal ignore:line-length
		"msg": "The annotation \"features.operators.openshift.io/fips-compliant\" is either missing or has an unexpected value",
		"term": "features.operators.openshift.io/fips-compliant",
	}}

	assertions.assert_equal_results(olm.deny, expected) with input.image.files as {"manifests/csv.yaml": on_cutoff_manifest}
		with input.image.config.Labels as {olm.manifestv1: "manifests/"}
		with data.rule_data.allowed_olm_image_registry_prefixes as ["registry.io"]
		with data.rule_data.allowed_olm_resource_kinds as ["ClusterServiceVersion"]
		with data.rule_data.fips_exempt_created_before as "2025-01-31T00:00:00Z"
}

# Test: Bundle created just before cutoff is exempt
test_fips_exempt_just_before_cutoff if {
	# Create bundle with createdAt just before the cutoff date
	just_before_manifest := json.patch(manifest, [
		{"op": "remove", "path": "/metadata/annotations/features.operators.openshift.io~1fips-compliant"},
		{"op": "add", "path": "/metadata/annotations/createdAt", "value": "2025-01-30T23:59:59Z"},
	])

	# Should be exempt because it's before the cutoff
	assertions.assert_empty(olm.deny) with input.image.files as {"manifests/csv.yaml": just_before_manifest}
		with input.image.config.Labels as {olm.manifestv1: "manifests/"}
		with data.rule_data.allowed_olm_image_registry_prefixes as ["registry.io"]
		with data.rule_data.allowed_olm_resource_kinds as ["ClusterServiceVersion"]
		with data.rule_data.fips_exempt_created_before as "2025-01-31T00:00:00Z"
}

# Test: Invalid createdAt date format is NOT exempt (fail closed for security)
test_fips_not_exempt_invalid_date_format if {
	# Create bundle with invalid date format (not RFC3339)
	invalid_date_manifest := json.patch(manifest, [
		{"op": "remove", "path": "/metadata/annotations/features.operators.openshift.io~1fips-compliant"},
		{"op": "add", "path": "/metadata/annotations/createdAt", "value": "2025-01-15"},
	])

	# Should NOT be exempt because date format is invalid (fail closed)
	expected_deny := {{
		"code": "olm.feature_annotations_format",
		# regal ignore:line-length
		"msg": "The annotation \"features.operators.openshift.io/fips-compliant\" is either missing or has an unexpected value",
		"term": "features.operators.openshift.io/fips-compliant",
	}}

	assertions.assert_equal_results(olm.deny, expected_deny) with input.image.files as {"manifests/csv.yaml": invalid_date_manifest}
		with input.image.config.Labels as {olm.manifestv1: "manifests/"}
		with data.rule_data.allowed_olm_image_registry_prefixes as ["registry.io"]
		with data.rule_data.allowed_olm_resource_kinds as ["ClusterServiceVersion"]
		with data.rule_data.fips_exempt_created_before as "2025-01-31T00:00:00Z"

	# Should also emit a warning about the malformed date
	expected_warn := {{
		"code": "olm.malformed_created_at",
		# regal ignore:line-length
		"msg": "The createdAt annotation \"2025-01-15\" is not a valid RFC3339 timestamp. FIPS exemption for legacy bundles cannot be determined. Expected format: 2006-01-02T15:04:05Z or with timezone offset.",
	}}

	assertions.assert_equal_results(olm.warn, expected_warn) with input.image.files as {"manifests/csv.yaml": invalid_date_manifest}
		with input.image.config.Labels as {olm.manifestv1: "manifests/"}
		with data.rule_data.allowed_olm_image_registry_prefixes as ["registry.io"]
		with data.rule_data.allowed_olm_resource_kinds as ["ClusterServiceVersion"]
		with data.rule_data.fips_exempt_created_before as "2025-01-31T00:00:00Z"
}

# Test: Empty string createdAt value triggers warning (distinct from missing annotation)
test_fips_warns_on_empty_created_at if {
	# Create bundle with empty createdAt annotation
	empty_date_manifest := json.patch(manifest, [
		{"op": "remove", "path": "/metadata/annotations/features.operators.openshift.io~1fips-compliant"},
		{"op": "add", "path": "/metadata/annotations/createdAt", "value": ""},
	])

	# Should emit a warning about the empty/malformed date
	expected_warn := {{
		"code": "olm.malformed_created_at",
		# regal ignore:line-length
		"msg": "The createdAt annotation \"\" is not a valid RFC3339 timestamp. FIPS exemption for legacy bundles cannot be determined. Expected format: 2006-01-02T15:04:05Z or with timezone offset.",
	}}

	assertions.assert_equal_results(olm.warn, expected_warn) with input.image.files as {"manifests/csv.yaml": empty_date_manifest}
		with input.image.config.Labels as {olm.manifestv1: "manifests/"}
		with data.rule_data.allowed_olm_image_registry_prefixes as ["registry.io"]
		with data.rule_data.allowed_olm_resource_kinds as ["ClusterServiceVersion"]
		with data.rule_data.fips_exempt_created_before as "2025-01-31T00:00:00Z"
}

# Test: Timezone handling - bundle created before cutoff in different timezone is exempt
test_fips_exempt_with_timezone_offset if {
	# 2025-01-30T19:00:00-05:00 (EST) = 2025-01-31T00:00:00Z (UTC)
	# So 2025-01-30T18:59:59-05:00 is just before the cutoff
	timezone_manifest := json.patch(manifest, [
		{"op": "remove", "path": "/metadata/annotations/features.operators.openshift.io~1fips-compliant"},
		{"op": "add", "path": "/metadata/annotations/createdAt", "value": "2025-01-30T18:59:59-05:00"},
	])

	# Should be exempt because the actual instant is before the cutoff
	assertions.assert_empty(olm.deny) with input.image.files as {"manifests/csv.yaml": timezone_manifest}
		with input.image.config.Labels as {olm.manifestv1: "manifests/"}
		with data.rule_data.allowed_olm_image_registry_prefixes as ["registry.io"]
		with data.rule_data.allowed_olm_resource_kinds as ["ClusterServiceVersion"]
		with data.rule_data.fips_exempt_created_before as "2025-01-31T00:00:00Z"
}

# Test: Timezone handling - bundle created at cutoff in different timezone is NOT exempt
test_fips_not_exempt_with_timezone_at_cutoff if {
	# 2025-01-30T19:00:00-05:00 (EST) = 2025-01-31T00:00:00Z (UTC) exactly
	timezone_manifest := json.patch(manifest, [
		{"op": "remove", "path": "/metadata/annotations/features.operators.openshift.io~1fips-compliant"},
		{"op": "add", "path": "/metadata/annotations/createdAt", "value": "2025-01-30T19:00:00-05:00"},
	])

	# Should NOT be exempt because it's exactly at the cutoff (not strictly before)
	expected := {{
		"code": "olm.feature_annotations_format",
		# regal ignore:line-length
		"msg": "The annotation \"features.operators.openshift.io/fips-compliant\" is either missing or has an unexpected value",
		"term": "features.operators.openshift.io/fips-compliant",
	}}

	assertions.assert_equal_results(olm.deny, expected) with input.image.files as {"manifests/csv.yaml": timezone_manifest}
		with input.image.config.Labels as {olm.manifestv1: "manifests/"}
		with data.rule_data.allowed_olm_image_registry_prefixes as ["registry.io"]
		with data.rule_data.allowed_olm_resource_kinds as ["ClusterServiceVersion"]
		with data.rule_data.fips_exempt_created_before as "2025-01-31T00:00:00Z"
}

# Test: Invalid fips_exempt_created_before configuration surfaces as error
test_fips_invalid_cutoff_config if {
	expected := {{
		"code": "olm.required_olm_features_annotations_provided",
		# regal ignore:line-length
		"msg": "Rule data fips_exempt_created_before has invalid RFC3339 format: \"invalid-date\"",
		"severity": "failure",
	}}

	assertions.assert_equal_results(olm.deny, expected) with input.image.files as {"manifests/csv.yaml": manifest}
		with input.image.config.Labels as {olm.manifestv1: "manifests/"}
		with data.rule_data.allowed_olm_image_registry_prefixes as ["registry.io"]
		with data.rule_data.allowed_olm_resource_kinds as ["ClusterServiceVersion"]
		with data.rule_data.fips_exempt_created_before as "invalid-date"
}

test_required_olm_features_annotations_provided if {
	expected_empty := {{
		"code": "olm.required_olm_features_annotations_provided",
		# regal ignore:line-length
		"msg": "Rule data required_olm_features_annotations has unexpected format: (Root): Array must have at least 1 items",
		"severity": "failure",
	}}
	assertions.assert_equal_results(olm.deny, expected_empty) with input.image.files as {"manifests/csv.yaml": manifest}
		with input.image.config.Labels as {olm.manifestv1: "manifests/"}
		with data.rule_data.allowed_olm_image_registry_prefixes as ["registry.io"]
		with data.rule_data.required_olm_features_annotations as []
		with data.rule_data.allowed_olm_resource_kinds as ["ClusterServiceVersion"]

	d := [
		# Wrong type
		1,
		# Duplicated items
		"foo",
		"foo",
	]

	expected := {
		{
			"code": "olm.feature_annotations_format",
			"msg": "The annotation \"foo\" is either missing or has an unexpected value",
			"term": "foo",
		},
		{
			"code": "olm.feature_annotations_format",
			"msg": "The annotation '\\x01' is either missing or has an unexpected value",
			"term": 1,
		},
		{
			"code": "olm.required_olm_features_annotations_provided",
			"msg": "Rule data required_olm_features_annotations has unexpected format: (Root): array items[1,2] must be unique",
			"severity": "failure",
		},
		{
			"code": "olm.required_olm_features_annotations_provided",
			# regal ignore:line-length
			"msg": "Rule data required_olm_features_annotations has unexpected format: 0: Invalid type. Expected: string, given: integer",
			"severity": "failure",
		},
	}

	assertions.assert_equal_results(olm.deny, expected) with input.image.files as {"manifests/csv.yaml": manifest}
		with input.image.config.Labels as {olm.manifestv1: "manifests/"}
		with data.rule_data.allowed_olm_image_registry_prefixes as ["registry.io"]
		with data.rule_data.required_olm_features_annotations as d
		with data.rule_data.allowed_olm_resource_kinds as ["ClusterServiceVersion"]
}

test_csv_semver_format_bad_semver if {
	csv := json.patch(manifest, [{"op": "add", "path": "/spec/version", "value": "spam"}])

	expected := {{
		"code": "olm.csv_semver_format",
		"msg": "The ClusterServiceVersion spec.version, \"spam\", is not a valid semver",
	}}

	assertions.assert_equal_results(olm.deny, expected) with input.image.files as {"manifests/csv.yaml": csv}
		with input.image.config.Labels as {olm.manifestv1: "manifests/"}
		with data.rule_data.allowed_olm_image_registry_prefixes as ["registry.io"]
		with data.rule_data.allowed_olm_resource_kinds as ["ClusterServiceVersion"]
}

test_csv_semver_format_missing if {
	csv := json.patch(manifest, [{"op": "remove", "path": "/spec/version"}])

	expected := {{
		"code": "olm.csv_semver_format",
		"msg": "The ClusterServiceVersion spec.version, \"<MISSING>\", is not a valid semver",
	}}

	assertions.assert_equal_results(olm.deny, expected) with input.image.files as {"manifests/csv.yaml": csv}
		with input.image.config.Labels as {olm.manifestv1: "manifests/"}
		with data.rule_data.allowed_olm_image_registry_prefixes as ["registry.io"]
		with data.rule_data.allowed_olm_resource_kinds as ["ClusterServiceVersion"]
}

test_subscriptions_annotation_format if {
	path := "/metadata/annotations/operators.openshift.io~1valid-subscription"
	files := {
		"m/csv-no-annotations.yaml": json.patch(manifest, [{"op": "remove", "path": "/metadata/annotations"}]),
		"m/csv-invalid-json.yaml": json.patch(manifest, [{"op": "add", "path": path, "value": "invalid-json"}]),
		"m/csv-empty.yaml": json.patch(manifest, [{"op": "add", "path": path, "value": "[]"}]),
		"m/csv-dupes.yaml": json.patch(manifest, [{"op": "add", "path": path, "value": `["spam", "spam"]`}]),
		"m/csv-bad-type.yaml": json.patch(manifest, [{"op": "add", "path": path, "value": "[1]"}]),
	}

	expected := {
		{
			"code": "olm.subscriptions_annotation_format",
			"msg": "Value of operators.openshift.io/valid-subscription annotation is missing",
			"severity": "failure",
		},
		{
			"code": "olm.subscriptions_annotation_format",
			"msg": "Value of operators.openshift.io/valid-subscription annotation is not valid JSON",
			"severity": "failure",
		},
		{
			"code": "olm.subscriptions_annotation_format",
			# regal ignore:line-length
			"msg": "Value of operators.openshift.io/valid-subscription annotation is invalid: (Root): Array must have at least 1 items",
			"severity": "failure",
		},
		{
			"code": "olm.subscriptions_annotation_format",
			# regal ignore:line-length
			"msg": "Value of operators.openshift.io/valid-subscription annotation is invalid: (Root): array items[0,1] must be unique",
			"severity": "failure",
		},
		{
			"code": "olm.subscriptions_annotation_format",
			# regal ignore:line-length
			"msg": "Value of operators.openshift.io/valid-subscription annotation is invalid: 0: Invalid type. Expected: string, given: integer",
			"severity": "failure",
		},
	}

	assertions.assert_equal_results(olm.deny, expected) with input.image.files as files
		with input.image.config.Labels as {olm.manifestv1: "m/"}
		with data.rule_data.allowed_olm_image_registry_prefixes as ["registry.io"]
		with data.rule_data.allowed_olm_resource_kinds as ["ClusterServiceVersion"]
}

test_unpinned_snapshot_references_operator if {
	expected := {{
		"code": "olm.unpinned_snapshot_references",
		"msg": "The \"registry.io/repo/msd:no_digest\" image reference is not pinned in the input snapshot.",
		"term": "registry.io/repo/msd:no_digest",
	}}
	assertions.assert_equal_results(olm.deny, expected) with input.snapshot.components as [unpinned_component, component1]
		with data.rule_data.pipeline_intention as "release"
		with data.rule_data.allowed_olm_image_registry_prefixes as ["registry.io"]
		with ec.oci.image_manifest as `{"config": {"digest": "sha256:goat"}}`
		with input.image.ref as unpinned_component.containerImage
		with data.rule_data.allowed_olm_resource_kinds as ["ClusterServiceVersion"]
}

test_unpinned_snapshot_references_different_input if {
	assertions.assert_empty(olm.deny) with input.snapshot.components as [unpinned_component]
		with data.rule_data.pipeline_intention as "release"
		with data.rule_data.allowed_olm_image_registry_prefixes as ["registry.io"]
		with ec.oci.image_manifest as `{"config": {"digest": "sha256:goat"}}`
		with input.image.ref as pinned2
}

test_unmapped_references_in_operator if {
	expected := {{
		"code": "olm.unmapped_references",
		"msg": "The \"registry.io/repository/image2@sha256:tea\" CSV image reference is not in the snapshot or accessible.",
		"term": "registry.io/repository/image2@sha256:tea",
	}}

	assertions.assert_equal_results(olm.deny, expected) with input.snapshot.components as [component1]
		with input.image.files as {"manifests/csv.yaml": manifest}
		with data.rule_data as {"pipeline_intention": "release", "allowed_olm_image_registry_prefixes": ["registry.io"]}
		with data.rule_data.allowed_olm_resource_kinds as ["ClusterServiceVersion"]
		with ec.oci.image_manifest as _mock_image_partial
		with ec.oci.descriptor as mock_ec_oci_image_descriptor
		with input.image.config.Labels as {olm.manifestv1: "manifests/"}
}

test_unpinned_related_images if {
	expected_deny := {{
		"code": "olm.unpinned_related_images",
		"msg": "2 related images are not pinned with a digest: registry.io/repo/msd:latest, registry.io/repo/msd:latest.",
	}}

	assertions.assert_equal_results(olm.deny, expected_deny) with data.rule_data.pipeline_intention as "release"
		with data.rule_data.allowed_olm_image_registry_prefixes as ["registry.io"]
		with input.snapshot.components as [component0]
		with input.attestations as _with_related_images
		with input.image.ref as "registry.io/repository/image@sha256:image_digest"
		with ec.oci.image_manifest as _mock_unpinned_image_partial
		with ec.oci.blob as _mock_unpinned_blob
		with ec.oci.descriptor as mock_ec_oci_image_descriptor
}

test_inaccessible_related_images if {
	expected_deny := {{
		"code": "olm.inaccessible_related_images",
		"msg": "The \"registry.io/repository/image2@sha256:tea\" related image reference is not accessible.",
		"term": "registry.io/repository/image2@sha256:tea",
	}}

	assertions.assert_equal_results(olm.deny, expected_deny) with data.rule_data.pipeline_intention as "release"
		with data.rule_data.allowed_olm_image_registry_prefixes as ["registry.io"]
		with input.snapshot.components as [component1]
		with input.attestations as _with_related_images
		with input.image.ref as "registry.io/repository/image@sha256:image_digest"
		with ec.oci.image_manifest as _mock_image_partial
		with ec.oci.blob as _mock_blob
		with ec.oci.descriptor as mock_ec_oci_image_descriptor
}

mock_ec_oci_image_descriptor("registry.io/repository/image@sha256:cafe") := `{"config": {"digest": "sha256:cafe"}}`

mock_ec_oci_image_descriptor("registry.io/repository/image3@sha256:coffee") := `{"config": {"digest": "sha256:coffee"}}`

mock_ec_oci_image_descriptor("registry.io/repository/image2@sha256:tea") := false

mock_ec_oci_image_descriptor("registry.io/repo/msd:latest") := `{"config": {"digest": ""}}`

test_olm_ci_pipeline if {
	# Make sure no violations are thrown if it isn't a release pipeline
	# regal ignore:line-length
	assertions.assert_equal(false, metadata.pipeline_intention_match(rego.metadata.chain())) with data.rule_data as {"pipeline_intention": null}
}

test_mock_cafe_descriptor if {
	# Test case that uses the mock_ec_oci_image_descriptor for cafe image
	expected := `{"config": {"digest": "sha256:cafe"}}`
	assertions.assert_equal(mock_ec_oci_image_descriptor("registry.io/repository/image@sha256:cafe"), expected)
}

test_unmapped_references_none_found if {
	assertions.assert_empty(olm.deny) with input.snapshot.components as [component1, component2]
		with input.image.files as {"manifests/csv.yaml": manifest}
		with input.image.config.Labels as {olm.manifestv1: "manifests/"}
		with data.rule_data.allowed_olm_image_registry_prefixes as ["registry.io"]
		with data.rule_data.allowed_olm_resource_kinds as ["ClusterServiceVersion"]
}

test_allowed_registries if {
	# This should pass since registry.io is a member of allowed_olm_image_registry_prefixes
	assertions.assert_empty(olm.deny) with data.rule_data.pipeline_intention as "release"
		with data.rule_data.allowed_olm_image_registry_prefixes as ["registry.io", "registry.redhat.io"]
		with input.image.config.Labels as {olm.manifestv1: "manifests/"}
		with input.image.files as {"manifests/csv.yaml": manifest}
		with data.rule_data.allowed_olm_resource_kinds as ["ClusterServiceVersion"]
}

test_bundle_image_index if {
	descriptor := {"mediaType": "application/vnd.oci.image.index.v1+json"}

	expected_deny := {{
		"code": "olm.olm_bundle_multi_arch",
		"msg": "The \"registry.io/repository/image@sha256:cafe\" bundle image is a multi-arch reference.",
		"term": "registry.io/repository/image@sha256:cafe",
	}}

	assertions.assert_equal_results(olm.deny, expected_deny) with data.rule_data.pipeline_intention as "release"
		with data.rule_data.allowed_olm_image_registry_prefixes as ["registry.io", "registry.redhat.io"]
		with data.rule_data.allowed_olm_resource_kinds as ["ClusterServiceVersion"]
		with input.image.config.Labels as {olm.manifestv1: "manifests/"}
		with input.image.files as {"manifests/csv.yaml": manifest}
		with input.image.ref as pinned1
		with ec.oci.descriptor as descriptor
}

test_unallowed_registries if {
	expected := {
		{
			"code": "olm.allowed_registries",
			# regal ignore:line-length
			"msg": "The \"registry.io/repository/image@sha256:cafe\" CSV image reference is not from an allowed registry.",
			"term": "registry.io/repository/image",
		},
		{
			"code": "olm.allowed_registries",
			# regal ignore:line-length
			"msg": "The \"registry.io/repository/image2@sha256:tea\" CSV image reference is not from an allowed registry.",
			"term": "registry.io/repository/image2",
		},
	}

	# This expects failure as registry.io is not a member of allowed_olm_image_registry_prefixes
	assertions.assert_equal_results(olm.deny, expected) with data.rule_data.pipeline_intention as "release"
		with data.rule_data.allowed_olm_image_registry_prefixes as ["registry.access.redhat.com", "registry.redhat.io"]
		with data.rule_data.allowed_olm_resource_kinds as ["ClusterServiceVersion"]
		with input.image.config.Labels as {olm.manifestv1: "manifests/"}
		with input.image.files as {"manifests/csv.yaml": manifest}
}

test_allowed_registries_related if {
	expected_deny := {
		{
			"code": "olm.allowed_registries_related",
			"msg": "The \"registry.io/repository/image@sha256:cafe\" related image reference is not from an allowed registry.",
			"term": "registry.io/repository/image",
		},
		{
			"code": "olm.allowed_registries_related",
			"msg": "The \"registry.io/repository/image2@sha256:tea\" related image reference is not from an allowed registry.",
			"term": "registry.io/repository/image2",
		},
		{
			"code": "olm.allowed_registries_related",
			# regal ignore:line-length
			"msg": "The \"registry.io/repository/image3@sha256:coffee\" related image reference is not from an allowed registry.",
			"term": "registry.io/repository/image3",
		},
	}

	assertions.assert_equal_results(olm.deny, expected_deny) with data.rule_data.pipeline_intention as "release"
		with data.rule_data.allowed_olm_image_registry_prefixes as ["registry.access.redhat.com", "registry.redhat.io"]
		with input.snapshot.components as [component1, component2, component3]
		with input.attestations as _with_related_images
		with input.image.ref as "registry.io/repository/image@sha256:image_digest"
		with ec.oci.image_manifest as _mock_image_all
		with ec.oci.blob as _mock_blob
		with ec.oci.descriptor as mock_ec_oci_image_descriptor
}

_related_images := [pinned1, pinned2, pinned3]

_unpinned_related_images := [unpinned_related_img]

_manifests_all := {
	"registry.io/repository/image@sha256:related_digest": {"layers": [{
		"mediaType": olm._related_images_oci_mime_type,
		"digest": "sha256:related_blob_digest",
	}]},
	"registry.io/repository/image@sha256:cafe": {"config": {"digest": "sha256:cafe"}},
	"registry.io/repository/image2@sha256:tea": {"config": {"digest": "sha256:tea"}},
	"registry.io/repository/image3@sha256:coffee": {"config": {"digest": "sha256:coffee"}},
}

_manifests_partial := {
	"registry.io/repository/image@sha256:related_digest": {"layers": [{
		"mediaType": olm._related_images_oci_mime_type,
		"digest": "sha256:related_blob_digest",
	}]},
	"registry.io/repository/image@sha256:cafe": {"config": {"digest": "sha256:cafe"}},
}

_manifests_unpinned := {
	"registry.io/repository/image@sha256:related_digest": {"layers": [{
		"mediaType": olm._related_images_oci_mime_type,
		"digest": "sha256:related_unpinned_blob_digest",
	}]},
	"registry.io/repository/image@sha256:dosa": {"config": {"digest": "sha256:dosa"}},
}

_blobs := {"registry.io/repository/image@sha256:related_blob_digest": json.marshal(_related_images)}

unpinned_blob_key := "registry.io/repository/image@sha256:related_unpinned_blob_digest"

_unpinned_blobs := {unpinned_blob_key: json.marshal(_unpinned_related_images)}

_mock_image_all(ref) := _manifests_all[ref]

_mock_image_partial(ref) := _manifests_partial[ref]

_mock_unpinned_image_partial(ref) := _manifests_unpinned[ref]

_mock_blob(ref) := _blobs[ref]

_mock_unpinned_blob(ref) := _unpinned_blobs[ref]

_bundle := "registry.img/spam@sha256:4e388ab32b10dc8dbc7e28144f552830adc74787c1e2c0824032078a79f227fb"

_with_related_images := _attestations_with_attachment("sha256:related_digest")

_attestations_with_attachment(attachment) := attestations if {
	_slsav1_task_base := tekton_test.resolved_slsav1_task(
		"validate-fbc",
		[],
		[{
			"name": olm._related_images_result_name,
			"type": "string",
			"value": attachment,
		}],
	)
	slsav1_task = tekton_test.with_bundle(_slsav1_task_base, _bundle)

	attestations := [
		lib_test.att_mock_helper_ref(
			olm._related_images_result_name,
			attachment,
			"validate-fbc",
			_bundle,
		),
		tekton_test.slsav1_attestation([slsav1_task]),
	]
}

test_image_ref_with_digest if {
	img := {"repo": "registry.io/repo", "digest": "sha256:abc", "tag": "latest"}
	expected := "registry.io/repo@sha256:abc"
	assertions.assert_equal(olm._image_ref(img), expected)
}

test_image_ref_with_tag if {
	img := {"repo": "registry.io/repo", "digest": "", "tag": "latest"}
	expected := "registry.io/repo:latest"
	assertions.assert_equal(olm._image_ref(img), expected)
}

test_image_ref_with_repo_only if {
	img := {"repo": "registry.io/repo", "digest": "", "tag": ""}
	expected := "registry.io/repo"
	assertions.assert_equal(olm._image_ref(img), expected)
}

test_disallowed_olm_resource_kind if {
	expected := {{
		"code": "olm.allowed_resource_kinds",
		"msg": "The \"NetworkPolicy\" manifest kind is not in the list of OLM allowed resource kinds.",
		"term": "NetworkPolicy",
	}}

	assertions.assert_equal_results(olm.deny, expected) with input.image.config.Labels as {olm.manifestv1: "manifests/"}
		with input.image.files as {"manifests/networkpolicy.yaml": network_policy_manifest}
		with data.rule_data.allowed_olm_resource_kinds as ["foo", "bar"]
}

test_allowed_olm_resource_kind if {
	expected_empty := {}

	assertions.assert_equal_results(olm.deny, expected_empty) with input.image.config.Labels as {olm.manifestv1: "manifests/"}
		with input.image.files as {"manifests/service.yaml": service_manifest}
		with data.rule_data.allowed_olm_resource_kinds as ["Service"]
}
