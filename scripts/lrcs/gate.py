"""Fail-closed, whole-tuple provenance gate for the LRCS prototype.

This module delegates cryptography and artifact-digest matching to gh 2.101.0.
It NEVER authorizes from unverified bundle JSON or workflow-written predicate
identity fields. A caller must protect the inputs during this call and rehash the
same file immediately before immutable upload; this module does not deploy.

Source contracts inspected 2026-10-02:
https://github.com/cli/cli/blob/0cf1092493af067646fc5f3db9421c6a6ec9c938/pkg/cmd/attestation/verification/extensions.go
https://github.com/cli/cli/blob/0cf1092493af067646fc5f3db9421c6a6ec9c938/pkg/cmd/attestation/verification/sigstore.go
https://github.com/sigstore/sigstore-go/blob/v1.3.0/pkg/fulcio/certificate/summarize.go
https://github.com/sigstore/sigstore-go/blob/v1.3.0/pkg/fulcio/certificate/extensions.go

Pinned gh emits a JSON array of successfully verified records. Its certificate
extensions are FLAT inside verificationResult.signature.certificate. Its opaque
Sigstore rejection loses the underlying error; it is conservatively an unknown
operational error, not credited as a security detection. Live pilot confirmation
of the pinned executable and actual generated bundles remains required.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import subprocess
import time
import uuid

GH_VERSION = "2.101.0"
ISSUER = "https://token.actions.githubusercontent.com"
PREDICATE = "https://slsa.dev/provenance/v1"
EXIT_CODES = {"allow": 0, "block": 10, "operational_error": 20}
TUPLE_FIELDS = {
    "source_repository", "certificate_identity", "signer_digest",
    "source_digest", "source_ref", "predicate_type",
}
POLICY_FIELDS = {
    "schema_version", "policy_id", "github_cli_version", "oidc_issuer",
    "deny_self_hosted_runners", "allowed_tuples",
}


def _json_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      allow_nan=False).encode("utf-8")


def validate_policy(policy: dict) -> None:
    """Reject placeholders, wildcard identities, unsupported settings and typos."""
    if not isinstance(policy, dict) or set(policy) != POLICY_FIELDS:
        raise ValueError("policy fields must match the version 1.0 contract exactly")
    if policy["schema_version"] != "1.0" or policy["github_cli_version"] != GH_VERSION:
        raise ValueError("unsupported policy schema or GitHub CLI version")
    if policy["oidc_issuer"] != ISSUER or policy["deny_self_hosted_runners"] is not True:
        raise ValueError("the approved issuer and hosted-runner requirement are fixed")
    if not isinstance(policy["policy_id"], str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", policy["policy_id"]):
        raise ValueError("policy_id must be a bound nonempty identifier")
    rows = policy["allowed_tuples"]
    if not isinstance(rows, list) or not 1 <= len(rows) <= 32:
        raise ValueError("allowed_tuples must contain 1 to 32 complete rows")
    seen = set()
    for row in rows:
        if not isinstance(row, dict) or set(row) != TUPLE_FIELDS:
            raise ValueError("each allowed tuple must contain exactly six fields")
        if any(not isinstance(v, str) or not v or "__" in v or any(c.isspace() for c in v)
               for v in row.values()):
            raise ValueError("empty, symbolic or whitespace-containing tuple binding")
        repo = row["source_repository"]
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9][A-Za-z0-9_.-]*", repo):
            raise ValueError("source_repository must be one exact owner/repository")
        ref = row["source_ref"]
        if (not re.fullmatch(r"refs/(heads|tags)/[^ ~^:?*\[\\]+", ref)
                or any(part in ("", ".", "..") or part.startswith(".") or part.endswith(".lock")
                       for part in ref.split("/"))
                or ".." in ref or "@{" in ref or ref.endswith(".")):
            raise ValueError("source_ref must be one exact full Git head or tag ref")
        for key in ("source_digest", "signer_digest"):
            if not re.fullmatch(r"[0-9a-f]{40}", row[key]) or len(set(row[key])) == 1:
                raise ValueError(f"{key} must be a bound lowercase full Git SHA-1")
        identity = row["certificate_identity"]
        expected = (r"https://github\.com/" + re.escape(repo)
                    + r"/\.github/workflows/[A-Za-z0-9_.-]+\.ya?ml@" + re.escape(ref))
        if not re.fullmatch(expected, identity):
            raise ValueError("certificate_identity must bind this repository, ordinary workflow and ref")
        if row["predicate_type"] != PREDICATE:
            raise ValueError("unsupported provenance predicate")
        serialized = _json_bytes(row)
        if serialized in seen:
            raise ValueError("duplicate tuple")
        seen.add(serialized)


def _hash_file(path: Path) -> str:
    # File contents must remain stable even during the hashing operation.
    before = path.stat()
    if not stat.S_ISREG(before.st_mode) or path.is_symlink():
        raise ValueError("input must be a regular, nonsymlink file")
    h = hashlib.sha256()
    with path.open("rb") as handle:
        opened = os.fstat(handle.fileno())
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise ValueError("input changed while opening")
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(block)
        after = os.fstat(handle.fileno())
    current = path.stat()
    stable = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    if stable(before) != stable(after) or stable(before) != stable(current):
        raise ValueError("input changed while hashing")
    return h.hexdigest()


def _raw(value):
    if value is None:
        value = b""
    if isinstance(value, str):
        value = value.encode("utf-8")
    return {"utf8": value.decode("utf-8", errors="replace"),
            "base64": base64.b64encode(value).decode("ascii"),
            "sha256": hashlib.sha256(value).hexdigest()}


def _offered_subject_mismatch(bundle: Path, digest: str) -> bool:
    """Reject-only check; a claimed match NEVER establishes authenticity.

    A mismatching subject cannot authenticate the candidate bytes. Require all
    offered records to be recognized before this shortcut; unknown encodings
    remain the cryptographic verifier's responsibility.
    """
    try:
        raw = bundle.read_text(encoding="utf-8")
        try:
            records = [json.loads(raw)]
        except ValueError:
            records = [json.loads(line) for line in raw.splitlines() if line.strip()]
        if not records:
            return False
        for record in records:
            envelope = record["dsseEnvelope"]
            if envelope["payloadType"] != "application/vnd.in-toto+json":
                return False
            statement = json.loads(base64.b64decode(envelope["payload"], validate=True))
            subjects = statement["subject"]
            if statement["_type"] != "https://in-toto.io/Statement/v1" or not subjects:
                return False
            for subject in subjects:
                claimed = subject["digest"]["sha256"]
                if not isinstance(claimed, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", claimed):
                    return False
                if claimed.lower() == digest:
                    return False
        return True
    except (OSError, ValueError, KeyError, TypeError):
        return False


def _classify_failure(stderr: str, row: dict) -> tuple[str, str]:
    """Only pinned, post-cryptography extension diagnostics count as blocks.

    A final precise Error line AND the phase marker are necessary. No generic
    exit status, candidate text, substring 'digest', or Sigstore failure suffices.
    """
    clean = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", stderr)
    lines = [line.strip() for line in clean.splitlines() if line.strip()]
    if "✗ Policy verification failed" in lines:
        expected = {
            "SourceRepositoryOwnerURI": ("https://github.com/" + row["source_repository"].split("/")[0], "repository_not_allowed"),
            "SourceRepositoryURI": ("https://github.com/" + row["source_repository"], "repository_not_allowed"),
            "BuildSignerDigest": (row["signer_digest"], "signer_commit_not_allowed"),
            "SourceRepositoryDigest": (row["source_digest"], "source_commit_not_allowed"),
            "SourceRepositoryRef": (row["source_ref"], "source_ref_not_allowed"),
        }
        if lines:
            for field, (value, reason) in expected.items():
                prefix = f"Error: expected {field} to be {value}, got "
                if lines[-1].startswith(prefix):
                    # Includes missing (empty) extension; never authorizes it.
                    return "block", reason
    if "no valid Sigstore verifiers could be initialized" in clean or "verifier is not available (initialization may have failed)" in clean:
        return "operational_error", "service_or_transport_failure"
    return "operational_error", "unknown"


def _verified_rows(stdout: str, row: dict, digest: str, issuer: str):
    """Inspect each verified record independently; never combine attestations."""
    data = json.loads(stdout)
    if not isinstance(data, list) or not data:
        raise ValueError("verifier did not return a nonempty verified-record array")
    evidence = []
    expected = {
        "sourceRepositoryURI": ("https://github.com/" + row["source_repository"], "repository_not_allowed"),
        "subjectAlternativeName": (row["certificate_identity"], "workflow_identity_not_allowed"),
        "buildSignerDigest": (row["signer_digest"], "signer_commit_not_allowed"),
        "sourceRepositoryDigest": (row["source_digest"], "source_commit_not_allowed"),
        "sourceRepositoryRef": (row["source_ref"], "source_ref_not_allowed"),
        "issuer": (issuer, "unexpected_configuration"),
        "runnerEnvironment": ("github-hosted", "unexpected_configuration"),
    }
    malformed = False
    for index, entry in enumerate(data):
        try:
            result = entry["verificationResult"]
            cert = result["signature"]["certificate"]
            statement = result["statement"]
            if not isinstance(entry["attestation"], dict) or not isinstance(cert, dict):
                raise ValueError("missing linked attestation/certificate")
            if any(not isinstance(cert.get(key), str) or not cert[key] for key in expected):
                raise ValueError("missing authenticated certificate field")
            if not isinstance(statement["predicateType"], str) or not isinstance(statement["subject"], list):
                raise ValueError("missing verified predicate/subjects")
            failed = [reason for key, (value, reason) in expected.items() if cert[key] != value]
            # This is the signed statement from verified output, never the raw bundle.
            if statement["predicateType"] != row["predicate_type"]:
                failed.append("predicate_type_not_allowed")
            if not any(isinstance(s, dict) and isinstance(s.get("digest"), dict)
                       and s["digest"].get("sha256") == digest for s in statement["subject"]):
                # gh just claimed digest verification: disagreement is an adapter
                # contract/configuration error, not independent proof of an attack.
                failed.append("unexpected_configuration")
            evidence.append({"verified_index": index, "certificate": {k: cert[k] for k in expected},
                             "predicate_type": statement["predicateType"], "failed_predicates": failed})
            if not failed:
                return "allow", "tuple_matched", evidence
        except (KeyError, TypeError, ValueError):
            malformed = True
            evidence.append({"verified_index": index, "parse_error": "missing_or_invalid_verified_fields"})
    if malformed or any("unexpected_configuration" in e.get("failed_predicates", []) for e in evidence):
        return "operational_error", "unexpected_configuration", evidence
    return "block", evidence[0]["failed_predicates"][0], evidence


def verify_artifact(artifact: Path, bundle: Path | None, policy: dict,
                    runner=subprocess.run, *, acquisition_status: str = "available",
                    acquisition_elapsed_seconds: float = 0.0) -> dict:
    """Return a JSON-serializable decision; no writes, acquisition or deployment.

    Resolver owns its 10-second deadline. Pass its actual elapsed time here so
    acquisition plus verification stays within the 60-second gate budget.
    Only an explicit resolver `absent` status with bundle=None is evidence_absent.
    `unavailable`, absent local files and unreadable bundles are operational errors.
    `runner` must implement subprocess.run's call/return contract; tests inject a
    synthetic runner. No testing bypass is part of policy or production CLI.
    """
    started = time.monotonic()
    evidence = {"acquisition_status": acquisition_status,
                "acquisition_elapsed_seconds": acquisition_elapsed_seconds,
                "commands": [], "tuple_attempts": [], "github_cli_required": GH_VERSION}
    result = {"schema_version": "1.0", "decision_id": str(uuid.uuid4()),
              "outcome": "operational_error", "reason": "unknown",
              "deployment_attempted": False, "evidence": evidence}
    paths = []

    def finish(outcome, reason, detail=None):
        result.update(outcome=outcome, reason=reason, fail_closed=(outcome != "allow"))
        if detail:
            evidence["detail"] = detail
        for label, path, before in paths:
            try:
                after = _hash_file(path)
                evidence[f"{label}_sha256_after"] = after
                if after != before:
                    raise ValueError("input content changed during verification")
            except (OSError, ValueError) as error:
                evidence["superseded_decision"] = {"outcome": result["outcome"], "reason": result["reason"]}
                result.update(outcome="operational_error", reason="unexpected_configuration", fail_closed=True)
                evidence["input_instability"] = {"input": label, "detail": str(error)}
                break
        evidence["verification_elapsed_seconds"] = time.monotonic() - started
        elapsed = acquisition_elapsed_seconds if isinstance(acquisition_elapsed_seconds, (int, float)) and math.isfinite(acquisition_elapsed_seconds) else 0
        evidence["total_gate_elapsed_seconds"] = elapsed + evidence["verification_elapsed_seconds"]
        if evidence["total_gate_elapsed_seconds"] >= 60:
            evidence["superseded_decision"] = {"outcome": result["outcome"], "reason": result["reason"]}
            result.update(outcome="operational_error", reason="timeout", fail_closed=True)
        evidence["first_decision"] = {"stage": "provenance_gate", "outcome": result["outcome"], "reason": result["reason"]}
        return result

    def run(command):
        remaining = 60 - acquisition_elapsed_seconds - (time.monotonic() - started)
        if remaining <= 0:
            raise subprocess.TimeoutExpired(command, 0)
        env = dict(os.environ)
        env.update(GH_PROMPT_DISABLED="1", NO_COLOR="1", GH_HOST="github.com")
        env.pop("GH_DEBUG", None)
        env.pop("GH_FORCE_TTY", None)
        before = time.monotonic()
        record = {"argv": command, "timeout_seconds": remaining}
        evidence["commands"].append(record)
        try:
            process = runner(command, capture_output=True, check=False, timeout=remaining, env=env)
            record.update(returncode=process.returncode, stdout=_raw(process.stdout), stderr=_raw(process.stderr))
            return process.returncode, record["stdout"]["utf8"], record["stderr"]["utf8"]
        except subprocess.TimeoutExpired as error:
            record.update(timed_out=True, stdout=_raw(error.stdout), stderr=_raw(error.stderr))
            raise
        finally:
            record["elapsed_seconds"] = time.monotonic() - before

    try:
        validate_policy(policy)
        evidence["policy_id"] = policy["policy_id"]
        evidence["policy_canonical_sha256"] = hashlib.sha256(_json_bytes(policy)).hexdigest()
        if (isinstance(acquisition_elapsed_seconds, bool)
                or not isinstance(acquisition_elapsed_seconds, (int, float))
                or not math.isfinite(acquisition_elapsed_seconds) or acquisition_elapsed_seconds < 0):
            return finish("operational_error", "unexpected_configuration", "invalid acquisition elapsed time")
        if acquisition_status not in {"available", "absent", "unavailable"}:
            return finish("operational_error", "unexpected_configuration", "invalid typed acquisition status")
        artifact = Path(artifact).absolute()
        digest = _hash_file(artifact)
        paths.append(("artifact", artifact, digest))
        evidence["artifact_sha256_before"] = digest
        if acquisition_elapsed_seconds > 10:
            return finish("operational_error", "timeout", "evidence acquisition exceeded its 10-second deadline")
        if acquisition_status == "unavailable":
            return finish("operational_error", "service_or_transport_failure", "resolver reported unavailable; no fallback")
        if acquisition_status == "absent":
            if bundle is not None:
                return finish("operational_error", "unexpected_configuration", "absence status conflicts with bundle")
            return finish("block", "evidence_absent")
        if bundle is None:
            return finish("operational_error", "unexpected_configuration", "available status requires a local bundle")
        bundle = Path(bundle).absolute()
        if bundle.suffix not in {".json", ".jsonl"} or bundle == artifact:
            return finish("operational_error", "unexpected_configuration", "bundle must be a distinct .json/.jsonl file")
        bundle_digest = _hash_file(bundle)
        paths.append(("bundle", bundle, bundle_digest))
        evidence["bundle_sha256_before"] = bundle_digest
        if _offered_subject_mismatch(bundle, digest):
            evidence["subject_precheck"] = {"check": "offered_subject_mismatch", "authenticated": False}
            return finish("block", "artifact_digest_mismatch")
        code, stdout, _ = run(["gh", "--version"])
        if code or not re.match(r"^gh version 2\.101\.0(?:\s|$)", stdout):
            return finish("operational_error", "unexpected_configuration", "pinned gh version unavailable")
        unresolved = []
        rejections = []
        # File order is the protected policy's deterministic row order.
        for index, row in enumerate(policy["allowed_tuples"]):
            command = ["gh", "attestation", "verify", str(artifact), "--bundle", str(bundle),
                       "--hostname", "github.com", "--repo", row["source_repository"],
                       "--cert-identity", row["certificate_identity"], "--cert-oidc-issuer", policy["oidc_issuer"],
                       "--signer-digest", row["signer_digest"], "--source-digest", row["source_digest"],
                       "--source-ref", row["source_ref"], "--predicate-type", row["predicate_type"],
                       "--deny-self-hosted-runners", "--format=json"]
            code, stdout, stderr = run(command)
            attempt = {"tuple_index": index, "tuple": dict(row), "command_index": len(evidence["commands"]) - 1}
            if code == 0:
                try:
                    outcome, reason, records = _verified_rows(stdout, row, digest, policy["oidc_issuer"])
                    attempt["verified_records"] = records
                except (ValueError, TypeError, KeyError):
                    outcome, reason = "operational_error", "unexpected_configuration"
            else:
                outcome, reason = _classify_failure(stderr, row)
            attempt.update(outcome=outcome, reason=reason)
            evidence["tuple_attempts"].append(attempt)
            if outcome == "allow":
                evidence["matched_tuple_index"] = index
                return finish("allow", reason)
            (unresolved if outcome == "operational_error" else rejections).append(reason)
        if unresolved:
            return finish("operational_error", unresolved[0], "at least one allowed tuple remained unresolved")
        return finish("block", rejections[0], "every complete allowed tuple was conclusively rejected")
    except subprocess.TimeoutExpired:
        return finish("operational_error", "timeout")
    except (OSError, ValueError, TypeError) as error:
        return finish("operational_error", "unexpected_configuration", str(error))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact", required=True, type=Path)
    parser.add_argument("--bundle", type=Path)
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--evidence-status", choices=("available", "absent", "unavailable"), default="available")
    parser.add_argument("--acquisition-elapsed-seconds", type=float, default=0.0)
    args = parser.parse_args(argv)
    try:
        # Preserve original policy-file hash separately from canonical content hash.
        policy_bytes = args.policy.read_bytes()
        policy = json.loads(policy_bytes)
        result = verify_artifact(args.artifact, args.bundle, policy,
                                 acquisition_status=args.evidence_status,
                                 acquisition_elapsed_seconds=args.acquisition_elapsed_seconds)
        result["evidence"]["policy_file_sha256"] = hashlib.sha256(policy_bytes).hexdigest()
    except (OSError, ValueError) as error:
        result = {"schema_version": "1.0", "outcome": "operational_error", "reason": "unexpected_configuration",
                  "fail_closed": True, "deployment_attempted": False, "evidence": {"detail": str(error)}}
    try:
        # Evidence is private by default and never overwrites a prior attempt.
        fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(result, handle, indent=2, sort_keys=True, allow_nan=False)
            handle.write("\n")
    except (OSError, ValueError) as error:
        print(json.dumps({"outcome": "operational_error", "reason": "unexpected_configuration", "detail": f"cannot preserve decision: {error}"}))
        return 20
    print(json.dumps({"outcome": result["outcome"], "reason": result["reason"], "output": str(args.output)}))
    return EXIT_CODES[result["outcome"]]


if __name__ == "__main__":
    raise SystemExit(main())
