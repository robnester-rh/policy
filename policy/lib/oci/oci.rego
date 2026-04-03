package lib.oci

import data.lib.image
import rego.v1

# blob_from_image fetches the blob content of the first layer from an OCI
# image manifest identified by ref. This is useful when ref is a tag-based
# reference where ec.oci.blob cannot be used directly because it requires
# digest-based references.
blob_from_image(ref) := blob if {
	parsed := image.parse(ref)
	manifest := ec.oci.image_manifest(ref)
	layer := manifest.layers[0]
	blob_ref := image.str({"repo": parsed.repo, "digest": layer.digest})
	blob := ec.oci.blob(blob_ref)
}
