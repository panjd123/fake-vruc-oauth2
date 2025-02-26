import requests
import time

# Configuration (matching fake_vruc_server.py)
BASE_URL = "http://localhost:8000"
CLIENT_ID = "vruc_test_client"
CLIENT_SECRET = "vruc_test_secret"
REDIRECT_URI = "http://localhost:3000/auth/callback/vruc"
SCOPE = "userinfo profile"

def test_oauth_flow():
    print("Starting VRUC OAuth 2.0 Flow Test...\n")

    # Step 1: Request authorization code
    print("Step 1: Requesting authorization code...")
    auth_url = (
        f"{BASE_URL}/authorize?"
        f"client_id={CLIENT_ID}&"
        f"response_type=code&"
        f"scope={SCOPE}&"
        f"redirect_uri={REDIRECT_URI}&"
        f"state=test_state"
    )
    response = requests.get(auth_url, allow_redirects=False)
    if response.status_code != 307:
        print(f"Failed to get authorization code: {response.status_code} - {response.text}")
        return
    
    redirect_location = response.headers["Location"]
    print(f"Redirected to: {redirect_location}")
    
    # Extract code from redirect URL
    if "code=" not in redirect_location:
        print("No code found in redirect URL")
        return
    code = redirect_location.split("code=")[1].split("&")[0]
    print(f"Authorization Code: {code}\n")

    # Step 2: Exchange code for access token
    print("Step 2: Exchanging code for access token...")
    token_url = f"{BASE_URL}/token"
    token_data = {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "grant_type": "authorization_code",
        "code": code
    }
    token_response = requests.post(token_url, data=token_data)
    if token_response.status_code != 200:
        print(f"Failed to get access token: {token_response.status_code} - {token_response.text}")
        return
    
    token_json = token_response.json()
    access_token = token_json["access_token"]
    print(f"Access Token: {access_token}")
    print(f"Token Response: {token_json}\n")

    # Step 3: Get user info
    print("Step 3: Fetching user info...")
    user_url = f"{BASE_URL}/apis/oauth2/v1/user"
    headers = {"Authorization": f"Bearer {access_token}"}
    user_response = requests.get(user_url, headers=headers)
    if user_response.status_code != 200:
        print(f"Failed to get user info: {user_response.status_code} - {user_response.text}")
        return
    
    user_json = user_response.json()
    print(f"User Info: {user_json}\n")

    # Step 4: Get profile info
    print("Step 4: Fetching profile info...")
    profile_url = f"{BASE_URL}/apis/oauth2/v1/profile"
    profile_response = requests.get(profile_url, headers=headers)
    if profile_response.status_code != 200:
        print(f"Failed to get profile info: {profile_response.status_code} - {profile_response.text}")
        return
    
    profile_json = profile_response.json()
    print(f"Profile Info: {profile_json}\n")

    print("VRUC OAuth 2.0 Flow Test Completed Successfully!")

if __name__ == "__main__":
    # Ensure the fake server is running before executing the test
    print("Please ensure fake_vruc_server.py is running on http://localhost:8000")
    time.sleep(2)  # Give a moment to ensure the server is up
    test_oauth_flow()