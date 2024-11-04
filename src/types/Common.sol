// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @dev Struct representing a token header configuration
struct Header {
    bytes kid;
    bytes tokenType;
}

/// @dev Struct representing the base vTPM configuration
struct BaseVtpmConfig {
    bytes hwmodel;
    bytes swname;
    bytes imageDigest;
    bytes iss;
    bool secboot;
}

/// @dev Struct representing the full vTPM configuration
struct VtpmConfig {
    bytes32 digest;
    BaseVtpmConfig base;
    uint256 exp;
    uint256 iat;
}

// Custom reverts
error SignatureVerificationFailed();
error PayloadValidationFailed(string errorMsg);
