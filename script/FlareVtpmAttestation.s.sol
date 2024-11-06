// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {FlareVtpmAttestation} from "../contracts/FlareVtpmAttestation.sol";
import {Script, console} from "forge-std/Script.sol";

contract FlareVtpmAttestationScript is Script {
    FlareVtpmAttestation public flareVtpm;

    function setUp() public {}

    function run() public {
        vm.startBroadcast();

        flareVtpm = new FlareVtpmAttestation();

        vm.stopBroadcast();
    }
}
