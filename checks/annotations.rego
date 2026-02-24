package checks

import rego.v1

# Required annotations on policy rules
required_annotations := {
	"title",
	"description",
	"custom.short_name",
	"custom.failure_msg",
}

# returns Rego files corresponding to policy rules
policy_rule_files(namespaces) := {rule |
	some namespace, files in namespaces
	startswith(namespace, "data.policy") # look only in the policy namespace
	rule := {"namespace": namespace, "files": {file |
		some file in files
		not endswith(file, "_test.rego") # disregard test Rego files
	}}
}

# for annotations defined as:
# {
#   "<ann>": "..."
# }
# return set with single element "<ann>"
flat(annotation_name, annotation_definition) := result if {
	is_string(annotation_definition)
	result := {annotation_name}
}

# for annotations defined as:
# {
#   "<ann1>": {
#     "<ann2>": "...",
#     "<ann3>": "..."
#  }
# return set with elements "<ann1>.<ann2>" and "<ann1>.<ann3>"
flat(annotation_name, annotation_definition) := result if {
	is_object(annotation_definition)
	result := {x |
		some nested_name, _ in annotation_definition
		x := concat(".", [annotation_name, nested_name])
	}
}

all_rule_names contains name if {
	some policy_files in policy_rule_files(input.namespaces)
	some file in policy_files.files
	some annotation in input.annotations

	annotation.location.file == file

	name := sprintf("%s.%s", [policy_files.namespace, annotation.annotations.custom.short_name])
}

all_rule_names_ary := [name |
	some policy_files in policy_rule_files(input.namespaces)
	some file in policy_files.files
	some annotation in input.annotations

	annotation.location.file == file

	name := sprintf("%s.%s", [policy_files.namespace, annotation.annotations.custom.short_name])
]

# Validates that the policy rules have all required annotations
violation contains msg if {
	some policy_files in policy_rule_files(input.namespaces)

	some file in policy_files.files
	some annotation in input.annotations

	# just examine Rego files that declare policies
	annotation.location.file == file

	# ... and ignore non-rule annotations, e.g. package, document.
	annotation.annotations.scope == "rule"

	# gather all annotations in a dotted format (e.g. "custom.short_name")
	declared_annotations := union({a |
		some key, _ in annotation.annotations
		a := flat(key, annotation.annotations[key])
	})

	# what required annotations are missing
	missing_annotations := required_annotations - declared_annotations

	# if we have any?
	count(missing_annotations) > 0

	msg := sprintf("ERROR: Missing annotation(s) %s at %s:%d", [
		concat(", ", missing_annotations),
		file, annotation.location.row,
	])
}

# Validates that the `depends_on` annotation points to an existing rule
violation contains msg if {
	some policy_files in policy_rule_files(input.namespaces)

	some file in policy_files.files
	some annotation in input.annotations

	annotation.location.file == file

	some depends_on in annotation.annotations.custom.depends_on
	dependency_rule_name := sprintf("data.policy.release.%s", [depends_on])

	count({dependency_rule_name} & all_rule_names) == 0
	msg := sprintf("ERROR: Missing dependency rule %q at %s:%d", [dependency_rule_name, file, annotation.location.row])
}

# Validates that package.short_name is unique
violation contains msg if {
	some policy_files in policy_rule_files(input.namespaces)

	some file in policy_files.files
	some annotation in input.annotations

	annotation.location.file == file

	code := sprintf("%s.%s", [policy_files.namespace, annotation.annotations.custom.short_name])

	duplicates := [r | some r in all_rule_names_ary; r == code]

	count(duplicates) > 1

	msg := sprintf("ERROR: Found non-unique code %q at %s:%d", [code, file, annotation.location.row])
}

# Validates that the `effective_on` annotation has the correct syntax
violation contains msg if {
	some policy_files in policy_rule_files(input.namespaces)

	some file in policy_files.files
	some annotation in input.annotations

	annotation.location.file == file

	effective_on := annotation.annotations.custom.effective_on
	not time.parse_rfc3339_ns(effective_on)

	msg := sprintf("ERROR: wrong syntax of effective_on value %q at %s:%d", [effective_on, file, annotation.location.row])
}

# Validates that dependency collections are a superset of dependent rule collections
# This ensures that whenever a dependent rule runs, its dependencies are also evaluated.
#
# For example, if rule A is in collections [minimal, redhat, slsa3] and depends on rule B,
# then rule B must be in all three collections [minimal, redhat, slsa3]. Otherwise, when
# evaluating the slsa3 collection, rule A would run but rule B would not, breaking the
# dependency assumption.
violation contains msg if {
	collections_by_rule := _build_rule_collections_map(input.namespaces, input.annotations)

	some annotation in _annotated_rules(input.namespaces, input.annotations)
	some dependency_name in annotation.annotations.custom.depends_on

	dependent_rule_collections := annotation.annotations.custom.collections
	dependency_rule_name := sprintf("data.policy.release.%s", [dependency_name])

	# Get dependency collections, defaulting to empty array if not present
	dependency_collections := object.get(collections_by_rule, dependency_rule_name, [])

	missing_collections_set := _missing_from_dependency(dependent_rule_collections, dependency_collections)
	count(missing_collections_set) > 0

	# Convert set to array for consistent output formatting
	missing_collections := [c | some c in missing_collections_set]

	msg := sprintf(
		"ERROR: Dependency %q is missing from collections %v (required by rule at %s:%d which is in collections %v)",
		[
			dependency_name,
			missing_collections,
			annotation.location.file,
			annotation.location.row,
			dependent_rule_collections,
		],
	)
}

# Helper to get all policy rule annotations with their file locations
_annotated_rules(namespaces, annotations) := {annotation |
	some policy_files in policy_rule_files(namespaces)
	some file in policy_files.files
	some annotation in annotations
	annotation.location.file == file
}

# Returns collections that the dependent has but the dependency lacks
_missing_from_dependency(dependent_collections, dependency_collections) := missing if {
	dependent_set := {c | some c in dependent_collections}
	dependency_set := {c | some c in dependency_collections}
	missing := dependent_set - dependency_set
}

# Helper to build a map of rule names to their collections
# Returns a map where:
#   key: fully qualified rule name (e.g., "data.policy.release.attestation_type.known_attestation_type")
#   value: array of collection names the rule belongs to (e.g., ["minimal", "redhat", "slsa3"])
_build_rule_collections_map(namespaces, annotations) := {rule_name: annotation.annotations.custom.collections |
	some policy_files in policy_rule_files(namespaces)
	some file in policy_files.files
	some annotation in annotations
	annotation.location.file == file

	rule_name := sprintf("%s.%s", [policy_files.namespace, annotation.annotations.custom.short_name])
}
