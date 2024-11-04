//SPDX-License-Identifier: MIT
pragma solidity >=0.8.20;

/**
 * @title Interface standard that implement attestation contracts whose verification logic can be implemented
 * both on-chain and with Risc0 ZK proofs
 * @notice The interface simply provides two verification methods for a given attestation input.
 * The user can either pay a possibly hefty gas cost to fully verify an attestation fully on-chain
 */
interface IAttestation {
    /**
     * @notice Verifies an RSA-signed JWT and registers the token if verification succeeds.
     * @param header The Base64URL decoded JWT header as bytes.
     * @param payload The Base64URL decoded JWT payload as bytes.
     * @param signature The Base64URL decoded RSA signature of the JWT.
     * @return success True if the token was successfully verified and registered.
     */
    function verifyAndAttest(bytes calldata header, bytes calldata payload, bytes calldata signature)
        external
        returns (bool success);
}
