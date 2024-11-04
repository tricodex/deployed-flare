# Flare vTPM Attestation

Flare vTPM Attestation is a Solidity-based implementation designed to verify Virtual Trusted Platform Module (vTPM) quotes generated within Google Cloud Platform’s (GCP) Confidential Space. 
This solution enables the permissionless onboarding of multiple Trusted Execution Environments (TEEs) on Flare, establishing a verifiable chain of trust across the network.

## Requirements

- [Solidity](https://soliditylang.org) v0.8.20 or higher
- [Foundry](https://getfoundry.sh)

## Usage

Start by cloning the repository:

```bash
git clone https://github.com/dineshpinto/flare-vtpm-attestation
```

To compile the contracts, run:

```bash
forge build
```

To run the contract tests:

```bash
forge test -vv
```

- The `-vv` flag provides verbose output, useful for detailed test logging.
- To generate a gas report for the contract functions, use the `--gas-report` flag.

### Deploying the contracts

To deploy the contracts, you can use a Foundry script along with your preferred RPC URL and private key:

```bash
forge script script/FlareVtpmAttestation.s.sol:FlareVtpmAttestationScript --rpc-url <your_rpc_url> --private-key <your_private_key>
```

To maintain code consistency and adhere to Solidity style guidelines, format the code with:

```bash
forge fmt
```

## Gas costs

| src/FlareVtpmAttestation.sol:FlareVtpmAttestation contract |                 |         |         |         |         |
| ---------------------------------------------------------- | --------------- | ------- | ------- | ------- | ------- |
| Deployment Cost                                            | Deployment Size |         |         |         |         |
| 2262676                                                    | 10273           |         |         |         |         |
| Function Name                                              | min             | avg     | median  | max     | # calls |
| addOidcPubKey                                              | 259441          | 259441  | 259441  | 259441  | 4       |
| parseHeader                                                | 1261            | 1261    | 1261    | 1261    | 1       |
| parsePayload                                               | 1124982         | 1124982 | 1124982 | 1124982 | 1       |
| setVtpmConfig                                              | 256323          | 256323  | 256323  | 256323  | 4       |
| verifyAndAttest                                            | 1816353         | 1816353 | 1816353 | 1816353 | 1       |
| verifyRsaSignature                                         | 317251          | 317251  | 317251  | 317251  | 1       |
