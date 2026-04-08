# Backwards compatibility shim for external users.
#
# This package provides deprecated aliases for functions that have been
# reorganized into domain-specific packages. External demos, documentation,
# and integrations may still reference the old data.lib.* paths.
#
# New code should import from the specific packages directly:
# - data.lib.metadata.result_helper
# - data.lib.metadata.result_helper_with_term
# - data.lib.metadata.result_helper_with_severity
package lib

import rego.v1

import data.lib.metadata

# Deprecated: Use data.lib.metadata.result_helper instead
result_helper(chain, failure_sprintf_params) := metadata.result_helper(chain, failure_sprintf_params)

# Deprecated: Use data.lib.metadata.result_helper_with_term instead
result_helper_with_term(chain, failure_sprintf_params, term) := metadata.result_helper_with_term(
	chain,
	failure_sprintf_params,
	term,
)

# Deprecated: Use data.lib.metadata.result_helper_with_severity instead
result_helper_with_severity(chain, failure_sprintf_params, severity) := metadata.result_helper_with_severity(
	chain,
	failure_sprintf_params,
	severity,
)
