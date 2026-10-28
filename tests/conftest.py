"""Shared pytest configuration for the ITSM agent test suite.

The package is installed into the uv-managed virtual environment
(`uv sync`), so imports of ``itsm_agent`` resolve through the installed
package. No sys.path manipulation is required.

Test-phase markers (unit, contract, integration, security,
fault_injection, scenarios) are registered in ``pyproject.toml`` under
``[tool.pytest.ini_options]`` and enforced via ``--strict-markers``.
"""
