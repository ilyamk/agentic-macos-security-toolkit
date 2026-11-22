.PHONY: test test-fast test-live lint self-test

# Fast: static lint, schema contracts, fixtures, self-tests. No host collection.
test-fast: lint self-test
	./tests/unit/test_modular_architecture.sh
	./tests/unit/test_contract_consistency.sh
	./tests/unit/test_workflow_safety.sh
	./tests/unit/test_brewup.sh
	./tests/unit/test_workstation_audit.sh
	./tests/unit/test_endpoint_stream.sh
	./tests/unit/test_assessment_lifecycle.sh
	./tests/unit/test_developer_adapters.sh
	./tests/unit/test_local_advisers.sh
	./tests/unit/test_network_import.sh

# Live: runs real posture/triage/assessment/monitor on this Mac (several minutes).
test-live:
	./tests/test_macos_security_posture.sh
	./tests/test_macos_security_triage.sh
	./tests/test_assessment_runner.sh
	./tests/test_security_workflow_contracts.sh

test: test-fast test-live

self-test:
	./run-macos-security-assessment.sh --self-test >/dev/null
	./macos-security-triage.sh --self-test >/dev/null
	./macos-security-monitor.sh --self-test >/dev/null
	./macos-security-remediation.sh --self-test >/dev/null
	./validate-macos-security-report.sh --self-test >/dev/null
	./bin/macos-security self-test >/dev/null
	./tools/install-user-tools.sh --self-test >/dev/null
	./tools/workstation-audit/workstation-audit.sh --self-test >/dev/null

lint:
	shellcheck -x -s sh bin/* adapters/*.sh collectors/native/*.sh collectors/monitoring/*.sh detectors/*.sh lib/*.sh macos-security-*.sh run-macos-security-assessment.sh validate-macos-security-report.sh tests/*.sh tests/unit/*.sh tools/*.sh tools/ci/*.sh tools/brewup/brewup tools/workstation-audit/*.sh tests/fixtures/workstation-audit/bin/*
	@for file in schemas/*.json config/*.json config/profiles/*.json .github/ci-tools.json; do jq -e . "$$file" >/dev/null || exit 1; done
