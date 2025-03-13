# Flare vTPM Attestation Integration Guide

This guide explains how to set up and deploy the ChainContext backend with Flare vTPM Attestation integration. This integration allows the application to prove it's running in a secure Trusted Execution Environment (TEE) and provide verifiable proof of this on the Flare blockchain.

## 1. Prerequisites

- Google Cloud account with permissions to create Confidential VMs
- Flare wallet with some native tokens for deployment and transaction fees
- Git repository access for the ChainContext project
- Basic familiarity with Linux, Docker, and blockchain concepts

## 2. Setting Up a Google Cloud Confidential VM

### 2.1 Create a Confidential VM

1. Go to the Google Cloud Console
2. Navigate to Compute Engine > VM instances
3. Click "Create Instance"
4. Configure your VM with the following settings:
   - Machine type: n2d-standard-2 (required for the hackathon)
   - CPU platform: AMD Milan
   - Under "Confidential VM service":
     - Enable "Confidential VM"
     - Select "AMD SEV-SNP"
   - Boot disk: Ubuntu 22.04 LTS
   - Allow HTTP/HTTPS traffic

5. Create the VM and wait for it to start

You can also create the VM using the gcloud CLI:

```bash
gcloud compute instances create chaincontext-vm \
  --machine-type=n2d-standard-2 \
  --min-cpu-platform="AMD Milan" \
  --zone=us-central1-a \
  --confidential-compute-type=SEV_SNP \
  --image-family=ubuntu-2204-lts \
  --image-project=ubuntu-os-cloud \
  --tags=http-server,https-server
```

### 2.2 Connect to the VM and Set Up the Environment

1. SSH into the VM using the Google Cloud Console or gcloud command

2. Clone the ChainContext repository:
```bash
mkdir -p ~/apps/MPC/hackathons
cd ~/apps/MPC/hackathons
git clone https://github.com/yourusername/chaincontext.git
cd chaincontext/chaincontext-backend
```

3. Run the setup script as root:
```bash
chmod +x setup_confidential_vm.sh
sudo ./setup_confidential_vm.sh
```

4. Log out and back in for the changes to take effect

## 3. Deploying the Flare vTPM Attestation Contract

### 3.1 Clone the Flare vTPM Attestation Repository

```bash
git clone https://github.com/dineshpinto/flare-vtpm-attestation.git
cd flare-vtpm-attestation
```

### 3.2 Install Foundry

```bash
curl -L https://foundry.paradigm.xyz | bash
source ~/.bashrc
foundryup
```

### 3.3 Install Python Dependencies

```bash
cd py
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

### 3.4 Obtain an Attestation Token

Create a simple script to fetch an attestation token:

```bash
cat > get_token.py << 'EOF'
#!/usr/bin/env python3
import requests

def get_attestation_token():
    """Fetch an attestation token from the Google Cloud Metadata Server"""
    # The attestation endpoint is available at a well-known location in Confidential VMs
    attestation_url = "http://metadata.google.internal/computeMetadata/v1/instance/attestation-token"
    
    # The request must include the Metadata-Flavor header
    headers = {"Metadata-Flavor": "Google"}
    
    # Make the request
    response = requests.get(attestation_url, headers=headers)
    
    # Check if the request was successful
    if response.status_code == 200:
        return response.text
    else:
        raise Exception(f"Failed to get attestation token: {response.status_code}")

# Get the token
token = get_attestation_token()

# Save it to a file
with open("attestation_token.txt", "w") as f:
    f.write(token)

print("Attestation token saved to attestation_token.txt")
EOF

chmod +x get_token.py
./get_token.py
```

### 3.5 Prepare Contract Inputs

```bash
cp attestation_token.txt py/data/oidc.txt
cd py
python prepare_inputs.py
```

Take note of the output, which will include:
- The JWT token parts in hex format
- Configuration parameters for the contract
- Public key information for verification

### 3.6 Configure Deployment

Create a `.env` file with your configuration:

```bash
cp .env.example .env
```

Edit the `.env` file with your settings:

```
PRIVATE_KEY="your_private_key_here"
HWMODEL="GCP_AMD_SEV"
SWNAME="CONFIDENTIAL_SPACE"
IMAGE_DIGEST="sha256:your_chaincontext_image_digest_here"
ISS="https://confidentialcomputing.googleapis.com"
SECBOOT=true
```

You can get your image digest by running:

```bash
cd ~/apps/MPC/hackathons/chaincontext/chaincontext-backend
docker-compose build
docker images --digests
```

### 3.7 Deploy the Contract

```bash
cd ~/flare-vtpm-attestation
forge script script/FlareVtpmAttestation.s.sol:FlareVtpmAttestationScript --rpc-url https://flare-api.flare.network/ext/C/rpc --private-key $PRIVATE_KEY
```

Take note of the deployed contract address for the next step.

## 4. Configuring ChainContext with vTPM Integration

### 4.1 Update Environment Variables

Edit the `.env` file in the ChainContext backend directory:

```bash
cd ~/apps/MPC/hackathons/chaincontext/chaincontext-backend
cp .env.example .env
```

Add the Flare vTPM Attestation contract address to your `.env` file:

```
FLARE_VTPM_ATTESTATION_ADDRESS=0x... # The contract address from the deployment step
```

Also configure your GEMINI_API_KEY and other required settings.

### 4.2 Build and Start the Application

```bash
docker-compose build
docker-compose up -d
```

### 4.3 Test the vTPM Integration

Run the test script to check if everything is working correctly:

```bash
source .venv/bin/activate
python test_vTPM.py
```

This script will:
1. Attempt to generate a vTPM attestation
2. Verify the attestation using the on-chain verifier
3. Test the API verification endpoint

## 5. Using vTPM Attestations in Production

### 5.1 Understanding Attestation Types

ChainContext now supports three types of attestations:

1. **GCP vTPM Attestation**: Generated on Google Cloud Confidential VMs using the Google Attestation Service. This provides cryptographic proof of the VM's secure state and the running container image.

2. **TPM-based Attestation**: Uses the physical TPM device for attestation. This is more generic and can work on different platforms with TPM 2.0 support.

3. **Simulated Attestation**: Used for development environments without TEE capabilities. This is not secure for production use.

### 5.2 Verification Process

When an attestation is verified:

1. The system checks the attestation type (gcp_vtpm, tpm, or simulated)
2. For vTPM attestations, it calls the FlareVtpmAttestation contract's `verifyAndAttest` function
3. For TPM attestations, it calls the TeeV1Verifier contract's `verifyAttestation` function
4. For simulated attestations, it returns a simulated successful verification

### 5.3 Best Practices for Production

- **Renew Attestations Regularly**: vTPM tokens have an expiration time, typically around 1 hour
- **Monitor Verification Status**: Set up alerts for failed verifications
- **Use Dedicated TEE Hardware**: For production, use dedicated instances with TEE capabilities
- **Key Management**: Store private keys securely, preferably in a hardware security module
- **Regular Updates**: Keep the TEE firmware and software up to date

## 6. Troubleshooting

### 6.1 vTPM Token Issues

If you can't obtain a vTPM token, check:
- Is the VM a Confidential VM with SEV-SNP enabled?
- Does the service account have the appropriate permissions?
- Can you access the metadata server?

You can test the metadata server access with:

```bash
curl "http://metadata.google.internal/computeMetadata/v1/instance/id" -H "Metadata-Flavor: Google"
```

### 6.2 Contract Verification Failures

Common issues include:
- **Invalid expiry time**: The JWT token has expired - fetch a fresh token
- **Public key not found**: Ensure the public key is registered in the contract
- **Invalid image digest**: The container image digest doesn't match the expected value

### 6.3 TPM Device Access

If there are issues accessing the TPM device:
- Check if `/dev/tpm0` exists
- Ensure permissions are correct: `sudo chmod 666 /dev/tpm0`
- Verify the TPM is properly initialized: `tpm2_getcap properties-fixed`

## 7. Conclusion

By integrating Flare vTPM Attestation, ChainContext now provides verifiable proof that it's running in a secure TEE environment. This enhances trust in the system's outputs and fulfills the requirements of the Flare x Google Verifiable AI Hackathon.

The flow is:
1. ChainContext runs in a Google Cloud Confidential VM
2. It obtains vTPM attestation tokens proving its TEE environment
3. These tokens are verified and registered on the Flare blockchain
4. Users can verify on-chain that the system is running in a legitimate TEE

This creates a trustless, verifiable AI system that aligns perfectly with the goals of the Flare x Google Verifiable AI Hackathon.
