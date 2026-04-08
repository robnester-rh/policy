package lib_test

import rego.v1

import data.lib
import data.lib.assertions

# Test backwards compatibility shim works
test_result_helper_backwards_compat if {
	mock_chain := [{
		"annotations": {"custom": {
			"short_name": "test_rule",
			"failure_msg": "Test failed with %s",
		}},
		"path": ["data", "test", "deny"],
	}]

	result := lib.result_helper(mock_chain, ["param1"])

	assertions.assert_equal("test.test_rule", result.code)
	assertions.assert_equal("Test failed with param1", result.msg)
	result.effective_on # Should exist
}

test_result_helper_with_term_backwards_compat if {
	mock_chain := [{
		"annotations": {"custom": {
			"short_name": "test_rule",
			"failure_msg": "Test failed",
		}},
		"path": ["data", "test", "deny"],
	}]

	result := lib.result_helper_with_term(mock_chain, [], "test_term")

	assertions.assert_equal("test.test_rule", result.code)
	assertions.assert_equal("test_term", result.term)
}

test_result_helper_with_severity_backwards_compat if {
	mock_chain := [{
		"annotations": {"custom": {
			"short_name": "test_rule",
			"failure_msg": "Test failed",
		}},
		"path": ["data", "test", "deny"],
	}]

	result := lib.result_helper_with_severity(mock_chain, [], "warning")

	assertions.assert_equal("test.test_rule", result.code)
	assertions.assert_equal("warning", result.severity)
}
