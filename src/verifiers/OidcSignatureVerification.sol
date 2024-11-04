// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {RSA} from "@openzeppelin/contracts/utils/cryptography/RSA.sol";
import {RSAPubKey, Header} from "../types/OidcStructs.sol";
import {Base64} from "@openzeppelin/contracts/utils/Base64.sol";

contract OidcSignatureVerification is Ownable {
    /// @notice Event emitted when a new OIDC RSA public key is added
    event PubKeyAdded(bytes indexed kid, bytes e, bytes n);

    /// @notice Mapping of RSA public keys by Key ID (kid)
    mapping(bytes kid => RSAPubKey) internal pubKeys;

    /**
     * @dev Constructor that sets the deployer as the initial owner.
     */
    constructor() Ownable(msg.sender) {}

    function tokenType() external pure returns (bytes memory) {
        return bytes("OIDC");
    }

    /**
     * @dev Adds an OIDC RSA public key to the contract.
     * @param kid The Key ID (identifier for the key).
     * @param e The exponent of the RSA public key.
     * @param n The modulus of the RSA public key.
     */
    function addPubKey(bytes memory kid, bytes memory e, bytes memory n) external onlyOwner {
        pubKeys[kid] = RSAPubKey({e: e, n: n});
        emit PubKeyAdded(kid, e, n);
    }

    /**
     * @dev Verifies an RSA-signed JWT.
     * @param rawHeader The JWT header as bytes (after Base64URL decoding).
     * @param rawPayload The JWT payload as bytes (after Base64URL decoding).
     * @param rawSignature The RSA signature of the JWT (after Base64URL decoding).
     * @param header The parsed header.
     * @return verified True if the signature is verified.
     * @return digest The SHA256 hash of the signing input (header + "." + payload).
     */
    function verifySignature(
        bytes calldata rawHeader,
        bytes calldata rawPayload,
        bytes calldata rawSignature,
        Header calldata header
    ) public view returns (bool verified, bytes32 digest) {
        // Construct the signing input as per JWT standards
        string memory headerB64URL = Base64.encodeURL(rawHeader);
        string memory payloadB64URL = Base64.encodeURL(rawPayload);

        bytes memory signingInput = abi.encodePacked(headerB64URL, ".", payloadB64URL);

        // Compute the SHA256 hash of the signing input
        digest = sha256(signingInput);

        // Retrieve the RSA public key using the kid
        RSAPubKey storage rsaPublicKey = pubKeys[header.kid];

        // Verify the RSA signature
        verified = RSA.pkcs1Sha256(digest, rawSignature, rsaPublicKey.e, rsaPublicKey.n);
    }
}
