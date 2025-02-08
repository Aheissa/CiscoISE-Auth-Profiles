import csv
import requests
import getpass
import base64
import warnings
import json
from urllib3.exceptions import InsecureRequestWarning

# Suppress only the single InsecureRequestWarning from urllib3 needed
warnings.simplefilter('ignore', InsecureRequestWarning)

def get_credentials():
    username = input("Enter your username: ")
    password = getpass.getpass("Enter your password: ")
    return username, password

def test_credentials(headers, ise_api_url):
    test_url = f"{ise_api_url}/versioninfo"
    print(f"Testing credentials with URL: {test_url}")
    response = requests.get(test_url, headers=headers, verify=False)
    print(f"Response status code: {response.status_code}")
    if response.status_code == 200:
        print(" ====== Credentials are valid.=====")
        return True
    else:
        print(f" ===== !Failed to validate credentials.===== Status Code: {response.status_code}, Response: {response.text}")
        return False

def create_authorization_profile(profile_data, headers, ise_api_url):
    response = requests.post(ise_api_url, headers=headers, json=profile_data, verify=False)
    if response.status_code == 201:
        print(f"\n *** Successfully created profile: {profile_data['AuthorizationProfile']['name']}")
        print(json.dumps(profile_data["AuthorizationProfile"], indent=4))
    else:
        error_message = response.json().get("ERSResponse", {}).get("messages", [{}])[0].get("title", "No error message provided")
        print(f"\n !!! Failed to create profile: {profile_data['AuthorizationProfile']['name']}, Status Code: {response.status_code},\n Message: {error_message}")

def main():
    username, password = get_credentials()
    ise_server_ip = input("Provide ISE PAN IP: ")
    ise_api_url = f"https://{ise_server_ip}:9060/ers/config/authorizationprofile"
    
    # Encode the credentials for Basic Authentication
    credentials = f"{username}:{password}"
    encoded_credentials = base64.b64encode(credentials.encode('utf-8')).decode('utf-8')
    
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Authorization": f"Basic {encoded_credentials}"
    }

    if not test_credentials(headers, ise_api_url):
        return

    mandatory_fields = ["name", "accessType"]
    optional_fields = ["description", "daclName", "authzProfileType", "vlan_nameID", "WebRedirectionType", "acl", "portalName", "voiceDomainPermission"]

    with open('AP.csv', mode='r', encoding='utf-8-sig') as file:
        csv_reader = csv.DictReader(file)
        for row in csv_reader:
            if all(field in row for field in mandatory_fields):
                profile_data = {
                    "AuthorizationProfile": {
                        "name": row.get("name"),
                        "accessType": row.get("accessType"),
                        "reauth": {
                            "timer": 28800,
                            "connectivity": "RADIUS_REQUEST"
                            },
                        "advancedAttributes": [
                            {
                                "leftHandSideDictionaryAttribue": {
                                "AdvancedAttributeValueType": "AdvancedDictionaryAttribute",
                                "dictionaryName": "Radius",
                                "attributeName": "Idle-Timeout"},
                            "rightHandSideAttribueValue": {
                            "AdvancedAttributeValueType": "AttributeValue",
                            "value": "7200"}
                            }
                        ],
                    }
                }
                for field in optional_fields:
                    if row.get(field):
                        if field == "vlan_nameID":
                            profile_data["AuthorizationProfile"]["vlan"] = {"nameID": row.get(field), "tagID":"1"}
                        elif field == "WebRedirectionType":
                            profile_data["AuthorizationProfile"]["webRedirection"] = {
                                "WebRedirectionType": row.get(field),
                                "acl": row.get("acl", ""),
                                "portalName": row.get("portalName", "")
                            }
                        elif field == "voiceDomainPermission":
                            profile_data["AuthorizationProfile"]["voiceDomainPermission"] = True
                        elif field not in ["acl", "portalName"]:  # Exclude acl and portalName from being added directly
                            profile_data["AuthorizationProfile"][field] = row.get(field)
                create_authorization_profile(profile_data, headers, ise_api_url)

if __name__ == "__main__":
    main()
