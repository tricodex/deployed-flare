// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Base64} from "@openzeppelin/contracts/utils/Base64.sol";
import {RSA} from "@openzeppelin/contracts/utils/cryptography/RSA.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

import {
    VtpmConfig, BaseVtpmConfig, SignatureVerificationFailed, PayloadValidationFailed
} from "./types/VtpmStructs.sol";

/**
 * @title FlareVtpmAttestation
 * @dev Contract for verifying RSA-signed JWTs and registering vTPM attestations.
 */
contract FlareVtpmAttestation is Ownable {
    /// @notice Mapping of registered vTPM configurations by address
    mapping(address => VtpmConfig) public registeredQuotes;

    /// @notice Event emitted when a new quote is registered
    event QuoteRegistered(address indexed sender, VtpmConfig config);

    /// @notice Event emitted when the base vTPM configuration is updated
    event BaseVtpmConfigUpdated(string indexed imageDigest, string hwname, string swname, string iss, bool secboot);

    /// @notice Event emitted when a new OIDC RSA public key is added
    event OidcPubKeyAdded(bytes indexed kid, bytes e, bytes n);

    /// @notice The required base vTPM configuration for verification
    BaseVtpmConfig internal requiredConfig;

    /// @notice Mapping of RSA public keys by Key ID (kid)
    mapping(bytes => RSAPubKey) internal rsaPubKeys;

    /// @dev Struct representing an RSA public key
    struct RSAPubKey {
        bytes e; // Exponent
        bytes n; // Modulus
    }

    /**
     * @dev Constructor that sets the deployer as the initial owner.
     */
    constructor() Ownable(msg.sender) {}

    /**
     * @dev Adds an OIDC RSA public key to the contract.
     * @param kid The Key ID (identifier for the key).
     * @param e The exponent of the RSA public key.
     * @param n The modulus of the RSA public key.
     */
    function addOidcPubKey(bytes memory kid, bytes memory e, bytes memory n) external onlyOwner {
        rsaPubKeys[kid] = RSAPubKey({e: e, n: n});
        emit OidcPubKeyAdded(kid, e, n);
    }

    /**
     * @dev Sets the required base vTPM configuration for verification.
     * Only callable by the contract owner.
     * @param hwmodel The hardware model.
     * @param swname The software name.
     * @param imageDigest The image digest.
     * @param iss The issuer.
     * @param secboot Indicates if secure boot is enabled.
     */
    function setBaseVtpmConfig(
        string calldata hwmodel,
        string calldata swname,
        string calldata imageDigest,
        string calldata iss,
        bool secboot
    ) external onlyOwner {
        requiredConfig.hwmodel = bytes(hwmodel);
        requiredConfig.swname = bytes(swname);
        requiredConfig.imageDigest = bytes(imageDigest);
        requiredConfig.iss = bytes(iss);
        requiredConfig.secboot = secboot;

        emit BaseVtpmConfigUpdated(imageDigest, hwmodel, swname, iss, secboot);
    }

    /**
     * @dev Verifies an RSA-signed JWT and registers the token if verification succeeds.
     * @param header The JWT header as bytes (Base64URL decoded).
     * @param payload The JWT payload as bytes (Base64URL decoded).
     * @param signature The RSA signature of the JWT.
     * @return success True if the token was successfully verified and registered.
     */
    function verifyAndAttest(bytes calldata header, bytes calldata payload, bytes calldata signature)
        external
        returns (bool success)
    {
        // Parse the Key ID (kid) from the JWT header
        bytes memory kid = parseHeader(header);

        // Verify the RSA signature of the JWT
        (bool verified, bytes32 digest) = verifyRsaSignature(header, payload, signature, kid);
        if (!verified) {
            revert SignatureVerificationFailed();
        }

        // Parse the payload to extract the vTPM configuration
        VtpmConfig memory payloadConfig = parsePayload(payload);

        // Ensure that the payload contains the required fields
        if (payloadConfig.exp < block.timestamp) {
            revert PayloadValidationFailed("invalid 'exp' in payload");
        }
        if (payloadConfig.iat > block.timestamp) {
            revert PayloadValidationFailed("invalid 'iat' in payload");
        }
        if (keccak256(payloadConfig.base.iss) != keccak256(requiredConfig.iss)) {
            revert PayloadValidationFailed("invalid 'iss' in payload");
        }
        if (payloadConfig.base.secboot != requiredConfig.secboot) {
            revert PayloadValidationFailed("invalid 'secboot' in payload");
        }
        if (keccak256(payloadConfig.base.hwmodel) != keccak256(requiredConfig.hwmodel)) {
            revert PayloadValidationFailed("invalid 'hwmodel' in payload");
        }
        if (keccak256(payloadConfig.base.swname) != keccak256(requiredConfig.swname)) {
            revert PayloadValidationFailed("invalid 'swname' in payload");
        }
        if (keccak256(payloadConfig.base.imageDigest) != keccak256(requiredConfig.imageDigest)) {
            revert PayloadValidationFailed("invalid 'imageDigest' in payload");
        }

        // Assign the computed digest to the payload configuration
        payloadConfig.digest = digest;

        // Register the token
        registeredQuotes[msg.sender] = payloadConfig;

        emit QuoteRegistered(msg.sender, payloadConfig);

        return true;
    }

    /**
     * @dev Verifies an RSA-signed JWT.
     * @param header The JWT header as bytes (after Base64URL decoding).
     * @param payload The JWT payload as bytes (after Base64URL decoding).
     * @param signature The RSA signature of the JWT (after Base64URL decoding).
     * @param kid The Key ID used to look up the RSA public key.
     * @return verified True if the signature is verified.
     * @return digest The SHA256 hash of the signing input (header + "." + payload).
     */
    function verifyRsaSignature(
        bytes calldata header,
        bytes calldata payload,
        bytes calldata signature,
        bytes memory kid
    ) public view returns (bool verified, bytes32 digest) {
        // Construct the signing input as per JWT standards
        string memory headerB64URL = Base64.encodeURL(header);
        string memory payloadB64URL = Base64.encodeURL(payload);

        bytes memory signingInput = abi.encodePacked(headerB64URL, ".", payloadB64URL);

        // Compute the SHA256 hash of the signing input
        digest = sha256(signingInput);

        // Retrieve the RSA public key using the kid
        RSAPubKey storage rsaPublicKey = rsaPubKeys[kid];

        // Verify the RSA signature
        verified = RSA.pkcs1Sha256(digest, signature, rsaPublicKey.e, rsaPublicKey.n);
    }

    /**
     * @dev Parses the Key ID (kid) from the JWT header.
     * @param header The JWT header as bytes (after Base64URL decoding).
     * @return kid The Key ID extracted from the header.
     */
    function parseHeader(bytes calldata header) public pure returns (bytes memory kid) {
        // Extract the 'kid' field from the header
        // Assumes that the 'kid' is located at bytes 22 to 62 in the header
        kid = header[22:62];
    }

    /**
     * @dev Parses the JWT payload to extract the vTPM configuration.
     * @param payload The JWT payload as bytes (after Base64URL decoding).
     * @return config The parsed vTPM configuration.
     */
    function parsePayload(bytes calldata payload) public view returns (VtpmConfig memory config) {
        // Extract the 'exp' (expiration time) from the payload
        config.exp = hexToTimestamp(payload[38:48]);

        // Extract the 'iat' (issued at time) from the payload
        config.iat = hexToTimestamp(payload[55:65]);

        // Extract the 'iss' (issuer) from the payload
        config.base.iss = payload[73:117];

        // Determine if 'secboot' (secure boot) is true or false in the payload
        if (contains(payload, bytes("true"))) {
            config.base.secboot = true;
        } else {
            config.base.secboot = false;
        }

        // Check if the payload contains the required 'hwmodel'
        if (contains(payload, requiredConfig.hwmodel)) {
            config.base.hwmodel = requiredConfig.hwmodel;
        }

        // Check if the payload contains the required 'swname'
        if (contains(payload, requiredConfig.swname)) {
            config.base.swname = requiredConfig.swname;
        }

        // Check if the payload contains the required 'imageDigest'
        if (contains(payload, requiredConfig.imageDigest)) {
            config.base.imageDigest = requiredConfig.imageDigest;
        }
    }

    /**
     * @dev Checks if a bytes sequence (needle) exists within another bytes sequence (haystack).
     * @param haystack The bytes sequence to search within.
     * @param needle The bytes sequence to search for.
     * @return exists True if the needle is found within the haystack.
     */
    function contains(bytes memory haystack, bytes memory needle) internal pure returns (bool exists) {
        // Edge cases
        if (needle.length == 0) {
            return true; // An empty needle is always found
        }
        if (needle.length > haystack.length) {
            return false; // Needle longer than haystack can't be found
        }

        // Use a sliding window to compare slices
        for (uint256 i = 0; i <= haystack.length - needle.length; i++) {
            bool matchFound = true;
            for (uint256 j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) {
                    matchFound = false;
                    break;
                }
            }
            if (matchFound) {
                return true;
            }
        }
        return false;
    }

    /**
     * @dev Converts a bytes array representing an ASCII decimal number to uint256.
     * @param hexBytes The bytes array to convert.
     * @return result The uint256 representation of the ASCII decimal number.
     */
    function hexToTimestamp(bytes memory hexBytes) internal pure returns (uint256 result) {
        require(hexBytes.length == 10, "Input should be 10 bytes long"); // solhint-disable-line gas-custom-errors

        for (uint256 i = 0; i < hexBytes.length; i++) {
            uint8 byteValue = uint8(hexBytes[i]);
            // Ensure it's a digit (0-9)
            require(byteValue >= 0x30 && byteValue <= 0x39, "Invalid character"); // solhint-disable-line gas-custom-errors
            result = result * 10 + (byteValue - 0x30); // Convert ASCII to integer
        }
    }
}
