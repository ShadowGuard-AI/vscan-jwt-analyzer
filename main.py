#!/usr/bin/env python3

import argparse
import base64
import binascii
import hashlib
import hmac
import json
import logging
import sys
import time

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

HMAC_ALGORITHMS = {
    "HS256": hashlib.sha256,
    "HS384": hashlib.sha384,
    "HS512": hashlib.sha512,
}
ASYMMETRIC_ALGORITHMS = ["RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512"]


class JWTAnalysisError(Exception):
    """Custom exception for JWT analysis errors."""
    pass


def _is_numeric_date(value):
    """True for a JSON NumericDate: an int or float, but not a bool."""
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def setup_argparse():
    """Sets up the argument parser for the CLI."""
    parser = argparse.ArgumentParser(description="Analyzes JWT (JSON Web Tokens) for common vulnerabilities.")
    parser.add_argument("jwt", help="The JWT to analyze.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output (debug logging).")
    parser.add_argument("--secret", action="append", default=[], metavar="CANDIDATE",
                        help="Operator supplied candidate secret for the weak secret test. May be given more than once. Results are reported by candidate index only; candidate values are never printed.")
    parser.add_argument("--secret-file", default=None, metavar="PATH",
                        help="Path to a file with one operator supplied candidate secret per line for the weak secret test. Results are reported by candidate index only.")
    parser.add_argument("--show-payload-values", action="store_true",
                        help="Show decoded payload claim values in full. Off by default: claim names and value types are reported, values are masked.")
    return parser


def _b64decode(segment):
    return base64.urlsafe_b64decode(segment + '=' * (-len(segment) % 4))


def _segments(jwt):
    parts = jwt.split(".")
    if len(parts) != 3:
        raise JWTAnalysisError(
            f"Token must have exactly three segments (header, payload, signature); found {len(parts)}.")
    return parts


def decode_jwt_header(jwt):
    try:
        header_encoded = _segments(jwt)[0]
        header_decoded = _b64decode(header_encoded).decode('utf-8')
        return json.loads(header_decoded)
    except (IndexError, json.JSONDecodeError, UnicodeDecodeError, binascii.Error, ValueError) as e:
        raise JWTAnalysisError(f"Error decoding JWT header: {e}")


def decode_jwt_payload(jwt):
    try:
        payload_encoded = _segments(jwt)[1]
        payload_decoded = _b64decode(payload_encoded).decode('utf-8')
        return json.loads(payload_decoded)
    except (IndexError, json.JSONDecodeError, UnicodeDecodeError, binascii.Error, ValueError) as e:
        raise JWTAnalysisError(f"Error decoding JWT payload: {e}")


def analyze_algorithm(header):
    findings = []
    alg = header.get("alg")

    if not alg:
        findings.append("Warning: 'alg' field is missing.  This could indicate a serious vulnerability.")
        return findings

    if alg == "none":
        findings.append("CRITICAL: 'alg' is 'none'. Signature verification is disabled. HIGHLY VULNERABLE!")
    elif alg in HMAC_ALGORITHMS:
        findings.append(f"Info: Algorithm is {alg}, which is a standard HMAC algorithm.")
    elif alg in ASYMMETRIC_ALGORITHMS:
        findings.append(f"Info: Algorithm is {alg}, which is an asymmetric algorithm.")
    else:
        findings.append(f"Warning: Algorithm '{alg}' is not a standard or recommended algorithm.  Investigate further.")

    return findings


def analyze_jwt(jwt):
    results = {
        "header_analysis": [],
        "payload_analysis": [],
        "general_analysis": []
    }

    header = decode_jwt_header(jwt)
    payload = decode_jwt_payload(jwt)

    results["header"] = header
    results["payload"] = payload

    results["header_analysis"].extend(analyze_algorithm(header))

    now = time.time()
    if "exp" not in payload:
        results["payload_analysis"].append("Warning: 'exp' (expiration time) claim is missing. JWT might not expire.")
    elif not _is_numeric_date(payload["exp"]):
        results["payload_analysis"].append("Warning: 'exp' claim is not a number, so its expiration cannot be evaluated. A NumericDate is required.")
    elif payload["exp"] < now:
        results["payload_analysis"].append("Warning: Token is expired: the 'exp' claim is in the past.")
    else:
        results["payload_analysis"].append("Info: Token is not expired: the 'exp' claim is in the future.")

    if "iat" not in payload:
        results["payload_analysis"].append("Warning: 'iat' (issued at) claim is missing.")
    elif not _is_numeric_date(payload["iat"]):
        results["payload_analysis"].append("Warning: 'iat' claim is not a number. A NumericDate is required.")

    if "nbf" not in payload:
        results["payload_analysis"].append("Warning: 'nbf' (not before) claim is missing.")
    elif not _is_numeric_date(payload["nbf"]):
        results["payload_analysis"].append("Warning: 'nbf' claim is not a number, so its validity window cannot be evaluated. A NumericDate is required.")
    elif payload["nbf"] > now:
        results["payload_analysis"].append("Warning: Token is not yet valid: the 'nbf' claim is in the future.")

    return results


def verify_signature(jwt, secret=""):
    """Verify an HMAC JWT signature with the standard library.

    Computes HMAC (hashlib sha256, sha384, or sha512, per the HS256,
    HS384, or HS512 alg value) over the signing input and compares in
    constant time. Returns True only when the signature matches.
    alg 'none' never verifies: it returns False.
    """
    try:
        parts = jwt.split(".")
        if len(parts) != 3:
            logging.error("Token does not have three segments; signature cannot be verified.")
            return False
        header_b64, payload_b64, signature_b64 = parts
        header_json = json.loads(_b64decode(header_b64).decode("utf-8"))
        alg = header_json.get("alg")

        if alg == "none":
            logging.warning("Signature verification cannot succeed for alg 'none': the token is unsigned and must be treated as unverifiable and vulnerable.")
            return False

        hash_algorithm = HMAC_ALGORITHMS.get(alg)
        if hash_algorithm is None:
            logging.warning(f"Signature verification not implemented for algorithm: {alg}")
            return False

        if not secret:
            logging.warning("No candidate secret provided. Signature verification cannot be performed for this HMAC token.")
            return False

        message = f"{header_b64}.{payload_b64}"
        digest = hmac.new(secret.encode("utf-8"), message.encode("utf-8"), hash_algorithm).digest()
        expected_signature_b64 = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("utf-8")
        return hmac.compare_digest(expected_signature_b64, signature_b64)
    except Exception as e:
        logging.error(f"Error during signature verification setup: {e}")
        return False


def print_analysis_results(results, show_payload_values=False):
    print("---------------- JWT Analysis Report ----------------")
    if "header" in results:
        print("\nHeader:")
        # An embedded JWK can carry key material, so it is never printed;
        # the rest of the header is metadata and is shown as decoded.
        print(json.dumps(_redact_header(results["header"]), indent=4))
    if "payload" in results:
        print("\nPayload (claim names and value types; values masked unless --show-payload-values was given):")
        masked = {}
        for name, value in results["payload"].items():
            masked[name] = value if show_payload_values else f"<masked: {type(value).__name__}>"
        print(json.dumps(masked, indent=4))

    print("\nFindings:")

    if results["header_analysis"]:
        print("\nHeader Analysis:")
        for finding in results["header_analysis"]:
            print(f"- {finding}")

    if results["payload_analysis"]:
        print("\nPayload Analysis:")
        for finding in results["payload_analysis"]:
            print(f"- {finding}")

    if results["general_analysis"]:
        print("\nGeneral Analysis:")
        for finding in results["general_analysis"]:
            print(f"- {finding}")
    print("-----------------------------------------------------")


def _redact_header(header):
    redacted = dict(header)
    if "jwk" in redacted:
        redacted["jwk"] = "<masked: embedded JWK not shown>"
    return redacted


def load_candidates(args):
    candidates = list(args.secret)
    if args.secret_file:
        try:
            with open(args.secret_file, "r") as f:
                for line in f:
                    # Strip both CR and LF so candidates never carry a
                    # line ending character into the HMAC input.
                    line = line.rstrip("\r\n")
                    if line:
                        candidates.append(line)
        except OSError as e:
            print(f"Error: could not read secret file: {e}")
            sys.exit(1)
    return candidates


def main():
    parser = setup_argparse()
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug("Verbose mode enabled.")

    jwt = args.jwt
    if not jwt:
        print("Error: JWT must be provided.")
        sys.exit(1)

    try:
        analysis_results = analyze_jwt(jwt)
    except JWTAnalysisError as e:
        logging.error(f"Could not decode the token: {e}")
        print("Error: the input could not be decoded as a JWT, so no analysis was performed.")
        sys.exit(1)

    print_analysis_results(analysis_results, show_payload_values=args.show_payload_values)

    # Weak secret test: only against operator supplied candidates, and
    # only the candidate index and the outcome are ever reported.
    candidates = load_candidates(args)
    header = analysis_results.get("header", {})
    alg = header.get("alg")
    if alg == "none":
        print("\n[-] Signature verification: not applicable. The token uses alg 'none' and has no signature; see the CRITICAL finding above.")
    elif candidates:
        matched = False
        for index, candidate in enumerate(candidates, start=1):
            ok = verify_signature(jwt, secret=candidate)
            print(f"Weak secret test: candidate {index}: {'success' if ok else 'failure'}")
            matched = matched or ok
        if matched:
            print("[+] Signature verified against an operator supplied candidate secret: the token uses a weak, guessable secret.")
        else:
            print("[-] Signature did not verify against any operator supplied candidate.")
    else:
        print("\n[-] Signature verification not attempted: no operator supplied candidate secrets (use --secret or --secret-file for the weak secret test).")


if __name__ == "__main__":
    main()
