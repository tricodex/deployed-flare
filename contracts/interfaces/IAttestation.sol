//SPDX-License-Identifier: MIT
pragma solidity >=0.8.20;

/**
 * @title Interface standard that implement attestation contracts.
 */
interface IAttestation {
    /**
     * @notice Verifies an RSA-signed JWT and registers the token if verification succeeds.
     * @param rawHeader The Base64URL decoded JWT header as bytes.
     * @param rawPayload The Base64URL decoded JWT payload as bytes.
     * @param rawSignature The Base64URL decoded RSA signature of the JWT.
     * @return success True if the token was successfully verified and registered.
     */
    function verifyAndAttest(bytes calldata rawHeader, bytes calldata rawPayload, bytes calldata rawSignature)
        external
        returns (bool success);
}
