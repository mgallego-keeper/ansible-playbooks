#!/usr/bin/env python3
"""Perform an opt-in, read-only Keeper request using initialized KSM_CONFIG."""

import argparse
import contextlib
import importlib
import io
import json
import logging
import os
import re
import sys


DEFAULT_SERVER = "keepersecurity.com"
MAX_RECORD_COUNT = 2147483647
REQUIRED_CONFIG_KEYS = ("clientId", "privateKey", "appKey", "hostname")
SAFE_ERROR_TYPES = {
    "Exception", "ValueError", "TypeError", "KeyError", "ImportError",
    "ModuleNotFoundError", "ConnectionError", "TimeoutError", "OSError",
    "RuntimeError", "PermissionError", "KeyboardInterrupt", "SystemExit",
}
SERVER_PATTERN = re.compile(
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\Z",
)


class ProbeFailure(Exception):
    """Carry only fixed, non-sensitive failure labels."""

    def __init__(self, stage, error_type):
        super().__init__(error_type)
        self.stage = stage
        self.error_type = error_type


class SafeArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        raise ProbeFailure("arguments", "InvalidArguments")


class DiscardStream(io.TextIOBase):
    def writable(self):
        return True

    def write(self, text):
        return len(text)


@contextlib.contextmanager
def suppress_sdk_output():
    """Discard SDK output and restore the caller's logging configuration."""
    previous_disable = logging.root.manager.disable
    logging.disable(sys.maxsize)
    try:
        with contextlib.redirect_stdout(DiscardStream()):
            with contextlib.redirect_stderr(DiscardStream()):
                yield
    finally:
        logging.disable(previous_disable)


def failure_report(stage, error_type):
    return {"passed": False, "stage": stage, "error_type": error_type}


def initialized_config(expected_server):
    if (
        not isinstance(expected_server, str)
        or len(expected_server) > 253
        or SERVER_PATTERN.fullmatch(expected_server) is None
    ):
        raise ProbeFailure("configuration", "InvalidExpectedServer")
    raw_config = os.environ.get("KSM_CONFIG")
    if not raw_config or not raw_config.strip():
        raise ProbeFailure("configuration", "MissingConfiguration")
    try:
        config = json.loads(raw_config)
    except (TypeError, ValueError):
        raise ProbeFailure("configuration", "InvalidJSON") from None
    if not isinstance(config, dict):
        raise ProbeFailure("configuration", "InvalidConfiguration")
    if any(
        not isinstance(config.get(key), str) or not config[key].strip()
        for key in REQUIRED_CONFIG_KEYS
    ):
        raise ProbeFailure("configuration", "UninitializedConfiguration")
    if config["hostname"] != expected_server:
        raise ProbeFailure("configuration", "UnexpectedServer")

    if os.environ.get("KSM_TOKEN"):
        raise ProbeFailure("configuration", "UnexpectedTokenEnvironment")
    hostname_override = os.environ.get("KSM_HOSTNAME")
    if hostname_override and hostname_override != expected_server:
        raise ProbeFailure("configuration", "UnexpectedServerOverride")

    # The SDK can otherwise override an explicit TLS setting from this variable.
    skip_verify = os.environ.get("KSM_SKIP_VERIFY")
    if skip_verify is not None and skip_verify.lower() not in {
        "false", "0", "no", "off", "f", "n",
    }:
        raise ProbeFailure("configuration", "UnsafeTLSConfiguration")
    return config


def probe_connectivity(expected_server=DEFAULT_SERVER):
    """Fetch records once and return only a bounded, non-sensitive report."""
    stage = "configuration"
    with suppress_sdk_output():
        try:
            config = initialized_config(expected_server)
            stage = "imports"
            sdk = importlib.import_module("keeper_secrets_manager_core")
            storage_module = importlib.import_module(
                "keeper_secrets_manager_core.storage",
            )
            stage = "client"
            storage = storage_module.InMemoryKeyValueStorage(config=config)
            client = sdk.SecretsManager(config=storage, verify_ssl_certs=True)
            stage = "fetch"
            records = client.get_secrets()
            stage = "report"
            if type(records) is not list or len(records) > MAX_RECORD_COUNT:
                raise ProbeFailure(stage, "InvalidResponse")
            return {
                "passed": True,
                "server": expected_server,
                "record_count": len(records),
            }
        except ProbeFailure as error:
            return failure_report(error.stage, error.error_type)
        except BaseException as error:
            # SDK exits and exception messages must not escape into job output.
            error_type = type(error).__name__
            if error_type not in SAFE_ERROR_TYPES:
                error_type = "SDKError"
            return failure_report(stage, error_type)


def main(argv=None):
    parser = SafeArgumentParser(description=__doc__)
    parser.add_argument("--expected-server", default=DEFAULT_SERVER)
    try:
        args = parser.parse_args(argv)
        report = probe_connectivity(args.expected_server)
    except ProbeFailure as error:
        report = failure_report(error.stage, error.error_type)
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
