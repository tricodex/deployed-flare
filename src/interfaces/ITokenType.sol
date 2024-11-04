//SPDX-License-Identifier: MIT
pragma solidity >=0.8.0;

import {Header} from "../types/Common.sol";

interface ITokenType {
    /// @dev immutable
    function tokenType() external pure returns (bytes memory);

    function verifySignature(bytes calldata, bytes calldata, bytes calldata, Header calldata)
        external
        view
        returns (bool, bytes32);
}
