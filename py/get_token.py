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