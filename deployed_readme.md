# Flare vTPM Attestation - Deployment Report

## Contract Deployments

### FlareVtpmAttestation Contract
**Contract Address:** 0x93012953008ef9AbcB71F48C340166E8f384e985  
**Network:** Coston 2 (Flare Testnet)  
**Deployment Transaction:** 0x4368caecbb4f48c2e6cbccdeb2c814bebbc4f197e612ff893403971d7a3f86eb  
**Block:** 15893424
**Verification Status:** Verified on Blockscout

### OidcSignatureVerification Contract
**Contract Address:** 0x28432EC82268eE4A9fa051e9005DCea26ae21160  
**Network:** Coston 2 (Flare Testnet)  
**Deployment Transaction:** 0xf67f34d133fcfbd21672053af693b37affdf666a65ff79ab5fae52eb2970667a  
**Deployment Date:** March 14, 2024  
**Verification Status:** Verified on Blockscout

## Contract Configuration

### Base Configuration (FlareVtpmAttestation)
The FlareVtpmAttestation contract has been configured with the following parameters:

- **Hardware Model:** GCP_AMD_SEV
- **Software Name:** CONFIDENTIAL_SPACE
- **Image Digest:** sha256:a490f5528c8739a870bdb234068fa29a95b9b641d1b0a114564c9e7a0ed900d0
- **Issuer:** https://confidentialcomputing.googleapis.com
- **Secure Boot:** Enabled

### Verifier Registration
The OidcSignatureVerification contract has been registered with the FlareVtpmAttestation contract to handle OIDC token verification:

- **Registration Transaction:** 0x2a481f5e407658898da65bbb3127f84e1af0f3fc168e80f74792b4edd5174e92
- **Token Type:** OIDC

## Integration

These contracts can be integrated with ChainContext through the following environment variables:

```
FLARE_VTPM_ATTESTATION_ADDRESS=0x93012953008ef9AbcB71F48C340166E8f384e985
TEE_VERIFIER_ADDRESS=0x28432EC82268eE4A9fa051e9005DCea26ae21160
```

The backend can now use these contracts to verify attestations from Google Cloud Confidential VMs.

## Verification Process

To verify an attestation, the application follows these steps:

1. Collect vTPM attestation token from Google metadata service
2. Process the token into header, payload, and signature components
3. Call `verifyAndAttest(header, payload, signature)` on the FlareVtpmAttestation contract
4. The FlareVtpmAttestation contract routes the verification to the OidcSignatureVerification contract based on the token type
5. The OidcSignatureVerification contract verifies the signature using the registered RSA public keys
6. If verification succeeds, the attestation is registered for the caller's address

## Contract Verification Commands

### FlareVtpmAttestation Verification
```
forge verify-contract --rpc-url https://coston2-api.flare.network/ext/C/rpc --verifier blockscout --verifier-url 'https://coston2-explorer.flare.network/api/' 0x93012953008ef9AbcB71F48C340166E8f384e985 contracts/FlareVtpmAttestation.sol:FlareVtpmAttestation
```

### OidcSignatureVerification Verification
```
forge verify-contract --rpc-url https://coston2-api.flare.network/ext/C/rpc --verifier blockscout --verifier-url 'https://coston2-explorer.flare.network/api/' 0x28432EC82268eE4A9fa051e9005DCea26ae21160 contracts/verifiers/OidcSignatureVerification.sol:OidcSignatureVerification
```

## Additional Details

For complete integration guide, see `VTPM_INTEGRATION_GUIDE.md`.
