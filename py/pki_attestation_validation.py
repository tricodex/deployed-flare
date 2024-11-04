import base64
import datetime
import hashlib
import re
from pathlib import Path
from typing import Any

import jwt
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from OpenSSL.crypto import X509, X509Store, X509StoreContext


class InvalidCertificateChainError(Exception):
    pass


class CertificateParsingError(Exception):
    pass


class ValidatePKIError(Exception):
    pass


class PKICertificates:
    """Class to hold the leaf, intermediate, and root certificates"""

    def __init__(
        self,
        leaf_cert: x509.Certificate,
        intermediate_cert: x509.Certificate,
        root_cert: x509.Certificate,
    ) -> None:
        self.LeafCert = leaf_cert
        self.IntermediateCert = intermediate_cert
        self.RootCert = root_cert


def validate_pki_token(
    stored_root_cert: x509.Certificate, attestation_token: str
) -> dict[str, Any]:
    """Validates the PKI token returned from the attestation service is valid."""
    # IMPORTANT: The attestation token should be considered untrusted
    # until the certificate chain and the signature is verified.

    jwt_headers = jwt.get_unverified_header(attestation_token)

    if jwt_headers.get("alg") != "RS256":
        msg = f"ValidatePKIToken - got Alg: {jwt_headers.get('alg')}, want: RS256"
        raise ValidatePKIError(msg)

    # Additional Check: Validate the ALG in the header matches the certificate SPKI.
    # https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.7
    # This is included in Go's jwt.Parse function

    x5c_headers = jwt_headers.get("x5c")
    if x5c_headers is None:
        msg = "x5c header not present"
        raise ValidatePKIError(msg)

    certificates = extract_certificate_from_x5c_header(x5c_headers)

    # Verify the leaf certificate signature algorithm is SHA256WithRSA
    if not certificates.LeafCert.signature_hash_algorithm:
        msg = "signature_hash_algorithm not found"
        raise ValidatePKIError(msg)

    if certificates.LeafCert.signature_hash_algorithm.name != "sha256":
        msg = "leaf certificate signature algorithm is not SHA256WithRSA"
        raise ValidatePKIError(msg)

    # Verify the leaf certificate public key algorithm is RSA
    if not isinstance(certificates.LeafCert.public_key(), rsa.RSAPublicKey):
        msg = "leaf certificate public key algorithm is not RSA"
        raise ValidatePKIError(msg)

    # Verify the stored root cert is the same as the root cert returned in the token.
    # stored root cert is from the confidential computing well-known endpoint
    # https://confidentialcomputing.googleapis.com/.well-known/attestation-pki-root
    compare_certificates(stored_root_cert, certificates.RootCert)

    verify_certificate_chain(certificates)

    # Retrieve the leaf certificate's public key
    public_key = certificates.LeafCert.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    # Parse and verify the token using the leaf certificate's public key
    return jwt.decode(
        attestation_token,
        key=public_pem,
        algorithms=["RS256"],
        options={"verify_signature": False},
    )


def extract_certificate_from_x5c_header(
    x5c_headers: list[Any],
) -> PKICertificates:
    """Extracts the certificates from the given x5c header."""
    x5c = [str(header) for header in x5c_headers]

    # The PKI token x5c header should have 3 certificates - leaf, intermediate, and root
    num_x5c_certs = 3
    if len(x5c) != num_x5c_certs:
        msg = "incorrect number of certificates in x5c header, "
        f"expected 3 certificates, but got {len(x5c)}"
        raise ValueError(msg)

    leaf_cert = decode_and_parse_certificate(x5c[0])
    if not leaf_cert:
        msg = "cannot parse leaf certificate"
        raise CertificateParsingError(msg)

    intermediate_cert = decode_and_parse_certificate(x5c[1])
    if not intermediate_cert:
        msg = "cannot parse intermediate cert"
        raise CertificateParsingError(msg)

    root_cert = decode_and_parse_certificate(x5c[2])
    if not root_cert:
        msg = "cannot parse root certificate"
        raise CertificateParsingError(msg)

    return PKICertificates(leaf_cert, intermediate_cert, root_cert)


def decode_and_parse_certificate(
    certificate_str: str,
) -> x509.Certificate:
    """Decodes base64 PEM certificate and parses it into an x509 certificate."""
    certificate_str = re.sub(
        r"-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----|\s+",
        "",
        certificate_str,
    )
    cert_bytes = base64.b64decode(certificate_str)
    return x509.load_der_x509_certificate(cert_bytes, default_backend())


def verify_certificate_chain(certificates: PKICertificates) -> None:
    """Verifies the certificate chain from leaf to root."""
    if is_certificate_lifetime_invalid(certificates.LeafCert):
        msg = "leaf certificate is not valid"
        raise InvalidCertificateChainError(msg)

    if is_certificate_lifetime_invalid(certificates.IntermediateCert):
        msg = "intermediate certificate is not valid"
        raise InvalidCertificateChainError(msg)

    if is_certificate_lifetime_invalid(certificates.RootCert):
        msg = "root certificate is not valid"
        raise InvalidCertificateChainError(msg)

    # Use OpenSSL to verify the certificate chain
    store = X509Store()
    store.add_cert(X509.from_cryptography(certificates.RootCert))
    store.add_cert(X509.from_cryptography(certificates.IntermediateCert))

    # Verify the leaf certificate
    store_ctx = X509StoreContext(store, X509.from_cryptography(certificates.LeafCert))
    store_ctx.verify_certificate()


def is_certificate_lifetime_invalid(certificate: x509.Certificate) -> bool:
    """Checks if the certificate is invalid based on its validity period."""
    current_time = datetime.datetime.now(tz=datetime.UTC)
    if current_time < certificate.not_valid_before_utc.replace(tzinfo=datetime.UTC):
        return True
    return current_time > certificate.not_valid_after_utc.replace(tzinfo=datetime.UTC)


def compare_certificates(cert1: x509.Certificate, cert2: x509.Certificate) -> None:
    """Compares two certificate fingerprints."""
    fingerprint1 = hashlib.sha256(cert1.tbs_certificate_bytes).digest()
    fingerprint2 = hashlib.sha256(cert2.tbs_certificate_bytes).digest()
    if fingerprint1 != fingerprint2:
        msg = "certificate fingerprint mismatch"
        raise ValidatePKIError(msg)


if __name__ == "__main__":
    # Load the stored root certificate
    with Path("data/root_cert.pem").open("rb") as f:
        stored_root_cert_pem = f.read()
    stored_root_certificate = x509.load_pem_x509_certificate(
        stored_root_cert_pem, default_backend()
    )

    # Load the PKI attestation token to validate
    with Path("data/pki").open("r") as f:
        attestation_token = f.read()

    # Validate the PKI token
    verified_jwt = validate_pki_token(stored_root_certificate, attestation_token)
    print("JWT is valid and verified.")
    print("Payload:", verified_jwt)
