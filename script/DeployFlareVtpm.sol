// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Script, console} from "forge-std/Script.sol";

contract DeployFlareVtpm is Script {
    uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
    string hwmodel = vm.envString("HWMODEL");
    string swname = vm.envString("SWNAME");
    string imageDigest = vm.envString("IMAGE_DIGEST");
    string iss = vm.envString("ISS");
    bool secboot = vm.envBool("SECBOOT");

    function run() public {
        // Starting the broadcast of transactions from the deployer account
        vm.startBroadcast(deployerPrivateKey);

        // Deploy contracts via forge create
        console.log("Deploying contracts with parameters:");
        console.log("  Hardware Model:", hwmodel);
        console.log("  Software Name:", swname);
        console.log("  Image Digest:", imageDigest);
        console.log("  Issuer:", iss);
        console.log("  Secure Boot:", secboot);
        
        console.log("Use forge create to deploy FlareVtpmAttestation and OidcSignatureVerification");
        console.log("Then configure them manually after deployment");

        vm.stopBroadcast();
    }
}