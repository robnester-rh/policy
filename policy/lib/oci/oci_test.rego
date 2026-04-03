package lib.oci_test

import rego.v1

import data.lib.oci

test_blob_from_image if {
	ref := "registry.io/repository/image:some-tag"
	manifest := {"layers": [{
		"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
		"digest": "sha256:abc123",
		"size": 42,
	}]}

	result := oci.blob_from_image(ref) with ec.oci.image_manifest as manifest
		with ec.oci.blob as _mock_blob

	result == "blob content"
}

test_blob_from_image_with_digest_ref if {
	ref := "registry.io/repository/image@sha256:def456"
	manifest := {"layers": [{
		"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
		"digest": "sha256:abc123",
		"size": 42,
	}]}

	result := oci.blob_from_image(ref) with ec.oci.image_manifest as manifest
		with ec.oci.blob as _mock_blob

	result == "blob content"
}

test_blob_from_image_empty_layers if {
	manifest := {"layers": []}

	not oci.blob_from_image("registry.io/repository/image:tag") with ec.oci.image_manifest as manifest
		with ec.oci.blob as _mock_blob
}

# Verify the helper selects the first layer, not an arbitrary one.
test_blob_from_image_multi_layer if {
	manifest := {"layers": [
		{
			"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
			"digest": "sha256:first",
			"size": 10,
		},
		{
			"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
			"digest": "sha256:second",
			"size": 20,
		},
	]}

	result := oci.blob_from_image("registry.io/repo/img:tag") with ec.oci.image_manifest as manifest
		with ec.oci.blob as _mock_blob_multi

	result == "first blob"
}

# Mock that only returns a value for the expected digest ref, verifying
# that blob_from_image constructs the correct ref from the layer digest.
_mock_blob("registry.io/repository/image@sha256:abc123") := "blob content"

_mock_blob_multi("registry.io/repo/img@sha256:first") := "first blob"
