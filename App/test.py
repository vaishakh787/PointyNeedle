import os
from getpass import getpass
import plistlib as plist
import json
import uuid
import pbkdf2
import requests
import hashlib
import hmac
import base64
import locale
from datetime import datetime
import srp._pysrp as srp
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from Crypto.Hash import SHA256

# Callback GUI
SECOND_FACTOR_CALLBACK = None

# Created here so that it is consistent
USER_ID = uuid.uuid4()
DEVICE_ID = uuid.uuid4()

# Configure SRP library for compatibility with Apple's implementation
srp.rfc5054_enable()
srp.no_username_in_x()

# Disable SSL Warning
import urllib3
urllib3.disable_warnings()

ANISETTE_URL = 'http://127.0.0.1:6969'  # https://github.com/Dadoum/anisette-v3-server

def icloud_login_mobileme(username, password, second_factor='sms'):
    g = gsa_authenticate(username, password, second_factor)
    if not g:
        print("GSA authentication failed")
        return None
        
    pet = g["t"]["com.apple.gs.idms.pet"]["token"]
    adsid = g["adsid"]
    
    data = {
        "apple-id": username,
        "delegates": {"com.apple.mobileme": {}},
        "password": pet,
        "client-id": str(USER_ID),
    }
    
    headers = {
        "X-Apple-ADSID": adsid,
        "User-Agent": "com.apple.iCloudHelper/282 CFNetwork/1408.0.4 Darwin/22.5.0",
        "X-Mme-Client-Info": '<MacBookPro18,3> <Mac OS X;13.4.1;22F8> <com.apple.AOSKit/282 (com.apple.accountsd/113)>',
        "Content-Type": "text/x-xml-plist",
        "Accept": "text/x-xml-plist"
    }
    headers.update(generate_anisette_headers())
    
    print(f"Making request to iosbuddy/loginDelegates...")
    r = requests.post(
        "https://setup.icloud.com/setup/iosbuddy/loginDelegates",
        auth=(username, pet),
        data=plist.dumps(data),
        headers=headers,
        verify=False,
        timeout=30
    )
    
    print(f"Response status: {r.status_code}")
    
    if r.status_code == 200:
        try:
            result = plist.loads(r.content)
            print("Successfully got response from iosbuddy/loginDelegates")
            return result
        except Exception as e:
            print(f"Failed to parse plist response: {e}")
            print(f"Raw response: {r.content[:500]}")
            return None
    else:
        print(f"Request failed: {r.text[:200]}")
        return None

def gsa_authenticate(username, password, second_factor='sms'):
    print(f"Starting GSA authentication for {username}")
    
    # Password is None as we'll provide it later
    usr = srp.User(username, bytes(), hash_alg=srp.SHA256, ng_type=srp.NG_2048)
    _, A = usr.start_authentication()
    
    r = gsa_authenticated_request({"A2k": A, "ps": ["s2k", "s2k_fo"], "u": username, "o": "init"})
    
    if r["sp"] not in ["s2k", "s2k_fo"]:
        print(f"This implementation only supports s2k and s2k_fo. Server returned {r['sp']}")
        return None
    
    print(f"Using protocol: {r['sp']}")
    
    # Change the password out from under the SRP library, as we couldn't calculate it without the salt.
    usr.p = encrypt_password(password, r["s"], r["i"], r["sp"])
    M = usr.process_challenge(r["s"], r["B"])
    
    # Make sure we processed the challenge correctly
    if M is None:
        print("Failed to process challenge")
        return None
    
    r = gsa_authenticated_request({"c": r["c"], "M1": M, "u": username, "o": "complete"})
    
    if "M2" not in r:
        print("Missing M2 in server response:", r)
        return None
    
    # Make sure that the server's session key matches our session key (and thus that they are not an imposter)
    usr.verify_session(r["M2"])
    if not usr.authenticated():
        print("Failed to verify session")
        return None
    
    print("SRP authentication successful, decrypting service data...")
    spd = decrypt_cbc(usr, r["spd"])
    
    # For some reason plistlib doesn't accept it without the header...
    PLISTHEADER = b"""\
<?xml version='1.0' encoding='UTF-8'?>
<!DOCTYPE plist PUBLIC '-//Apple//DTD PLIST 1.0//EN' 'http://www.apple.com/DTDs/PropertyList-1.0.dtd'>
"""
    spd = plist.loads(PLISTHEADER + spd)
    
    # Check if 2FA is required
    if "Status" in r and "au" in r["Status"] and r["Status"]["au"] in ["trustedDeviceSecondaryAuth", "secondaryAuth"]:
        print("2FA required, requesting code")
        
        # Replace bytes with strings for JSON serialization
        for k, v in spd.items():
            if isinstance(v, bytes):
                spd[k] = base64.b64encode(v).decode()
        
        if second_factor == 'sms':
            sms_second_factor(spd["adsid"], spd["GsIdmsToken"])
        elif second_factor == 'trusted_device':
            trusted_second_factor(spd["adsid"], spd["GsIdmsToken"])
        else:
            print(f"Unknown second factor method: {second_factor}")
            return None
            
        # Recursive call after 2FA
        print("Retrying authentication after 2FA...")
        return gsa_authenticate(username, password, second_factor)
        
    elif "Status" in r and "au" in r["Status"]:
        print(f"Unknown auth value {r['Status']['au']}")
        return None
    else:
        print("GSA authentication completed successfully")
        return spd

def gsa_authenticated_request(parameters):
    body = {
        "Header": {"Version": "1.0.1"},
        "Request": {"cpd": generate_cpd()},
    }
    body["Request"].update(parameters)
    
    headers = {
        "Content-Type": "text/x-xml-plist",
        "Accept": "*/*",
        "User-Agent": "akd/1.0 CFNetwork/978.0.7 Darwin/18.7.0",
        "X-MMe-Client-Info": '<MacBookPro18,3> <Mac OS X;13.4.1;22F8> <com.apple.AOSKit/282 (com.apple.dt.Xcode/3594.4.19)>'
    }
    
    resp = requests.post(
        "https://gsa.apple.com/grandslam/GsService2",
        headers=headers,
        data=plist.dumps(body),
        verify=False,
        timeout=30,
    )
    
    if resp.status_code != 200:
        print(f"GSA request failed with status {resp.status_code}")
        print(f"Response: {resp.content[:200]}")
        raise Exception(f"GSA request failed: {resp.status_code}")
    
    return plist.loads(resp.content)["Response"]

def generate_cpd():
    cpd = {
        # Many of these values are not strictly necessary, but may be tracked by Apple
        "bootstrap": True,  # All implementations set this to true
        "icscrec": True,  # Only AltServer sets this to true
        "pbe": False,  # All implementations explicitly set this to false
        "prkgen": True,  # I've also seen ckgen
        "svct": "iCloud",  # In certain circumstances, this can be 'iTunes' or 'iCloud'
    }
    cpd.update(generate_anisette_headers())
    return cpd

_ani_headers = None

def generate_anisette_headers():
    global _ani_headers
    if _ani_headers is None:
        print(f'Querying {ANISETTE_URL} for anisette headers')
        try:
            response = requests.get(ANISETTE_URL, timeout=10)
            h = response.json()
            a = {"X-Apple-I-MD": h["X-Apple-I-MD"], "X-Apple-I-MD-M": h["X-Apple-I-MD-M"]}
            a.update(generate_meta_headers(user_id=USER_ID, device_id=DEVICE_ID))
            _ani_headers = a
            print("Anisette headers generated successfully")
        except Exception as e:
            print(f"Failed to get anisette headers: {e}")
            raise
    return _ani_headers

def reset_headers():
    global _ani_headers
    _ani_headers = None

def generate_meta_headers(serial="0", user_id=uuid.uuid4(), device_id=uuid.uuid4()):
    return {
        "X-Apple-I-Client-Time": datetime.utcnow().replace(microsecond=0).isoformat() + "Z",
        "X-Apple-I-TimeZone": str(datetime.utcnow().astimezone().tzinfo),
        "loc": locale.getdefaultlocale()[0] or "en_US",
        "X-Apple-Locale": locale.getdefaultlocale()[0] or "en_US",
        "X-Apple-I-MD-RINFO": "17106176",  # either 17106176 or 50660608
        "X-Apple-I-MD-LU": base64.b64encode(str(user_id).upper().encode()).decode(),
        "X-Mme-Device-Id": str(device_id).upper(),
        "X-Apple-I-SRL-NO": serial,  # Serial number
    }

def encrypt_password(password, salt, iterations, protocol):
    assert protocol in ["s2k", "s2k_fo"]
    print(f"Encrypting password with {protocol}, {iterations} iterations")
    
    p = hashlib.sha256(password.encode("utf-8")).digest()
    if protocol == "s2k_fo":
        p = p.hex().encode("utf-8")
    return pbkdf2.PBKDF2(p, salt, iterations, SHA256).read(32)

def create_session_key(usr, name):
    k = usr.get_session_key()
    if k is None:
        raise Exception("No session key")
    return hmac.new(k, name.encode(), hashlib.sha256).digest()

def decrypt_cbc(usr, data):
    extra_data_key = create_session_key(usr, "extra data key:")
    extra_data_iv = create_session_key(usr, "extra data iv:")
    # Get only the first 16 bytes of the iv
    extra_data_iv = extra_data_iv[:16]
    
    # Decrypt with AES CBC
    cipher = Cipher(algorithms.AES(extra_data_key), modes.CBC(extra_data_iv))
    decryptor = cipher.decryptor()
    data = decryptor.update(data) + decryptor.finalize()
    
    # Remove PKCS#7 padding
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(data) + unpadder.finalize()

def set_callback(func):
    global SECOND_FACTOR_CALLBACK
    SECOND_FACTOR_CALLBACK = func

def trusted_second_factor(dsid, idms_token):
    print("Triggering trusted device 2FA...")
    identity_token = base64.b64encode((dsid + ":" + idms_token).encode()).decode()
    
    headers = {
        "Content-Type": "text/x-xml-plist",
        "User-Agent": "Xcode",
        "Accept": "text/x-xml-plist",
        "Accept-Language": "en-us",
        "X-Apple-Identity-Token": identity_token,
        "X-Apple-App-Info": "com.apple.gs.xcode.auth",
        "X-Xcode-Version": "11.2 (11B41)",
        "X-Mme-Client-Info": '<MacBookPro18,3> <Mac OS X;13.4.1;22F8> <com.apple.AOSKit/282 (com.apple.dt.Xcode/3594.4.19)>'
    }
    headers.update(generate_anisette_headers())
    
    # This will trigger the 2FA prompt on trusted devices
    try:
        requests.get(
            "https://gsa.apple.com/auth/verify/trusteddevice",
            headers=headers,
            verify=False,
            timeout=10,
        )
        print("2FA prompt sent to trusted devices")
    except Exception as e:
        print(f"Failed to trigger 2FA: {e}")
    
    # Prompt for the 2FA code
    if callable(SECOND_FACTOR_CALLBACK):
        code = SECOND_FACTOR_CALLBACK()
    else:
        code = input("Enter 2FA code from your trusted device: ").strip()
    
    if not code or len(code) != 6 or not code.isdigit():
        print("Invalid 2FA code format")
        return False
    
    headers["security-code"] = code
    
    # Send the 2FA code to Apple
    try:
        resp = requests.get(
            "https://gsa.apple.com/grandslam/GsService2/validate",
            headers=headers,
            verify=False,
            timeout=10,
        )
        if resp.ok:
            print("2FA successful")
            return True
        else:
            print(f"2FA failed: {resp.status_code}")
            return False
    except Exception as e:
        print(f"2FA validation error: {e}")
        return False

def sms_second_factor(dsid, idms_token):
    print("Triggering SMS 2FA...")
    identity_token = base64.b64encode((dsid + ":" + idms_token).encode()).decode()
    
    headers = {
        "User-Agent": "Xcode",
        "Accept-Language": "en-us",
        "X-Apple-Identity-Token": identity_token,
        "X-Apple-App-Info": "com.apple.gs.xcode.auth",
        "X-Xcode-Version": "11.2 (11B41)",
        "X-Mme-Client-Info": '<MacBookPro18,3> <Mac OS X;13.4.1;22F8> <com.apple.AOSKit/282 (com.apple.dt.Xcode/3594.4.19)>'
    }
    headers.update(generate_anisette_headers())
    
    # Request SMS code
    body = {"phoneNumber": {"id": 1}, "mode": "sms"}
    
    try:
        t = requests.put(
            "https://gsa.apple.com/auth/verify/phone/",
            json=body,
            headers=headers,
            verify=False,
            timeout=10
        )
        print("SMS 2FA code requested")
    except Exception as e:
        print(f"Failed to request SMS code: {e}")
    
    # Prompt for the 2FA code
    code = input("Enter SMS 2FA code: ").strip()
    
    if not code or len(code) != 6 or not code.isdigit():
        print("Invalid SMS code format")
        return False
    
    body['securityCode'] = {'code': code}
    
    # Send the 2FA code to Apple
    try:
        resp = requests.post(
            "https://gsa.apple.com/auth/verify/phone/securitycode",
            json=body,
            headers=headers,
            verify=False,
            timeout=10,
        )
        if resp.ok:
            print("SMS 2FA successful")
            return True
        else:
            print(f"SMS 2FA failed: {resp.status_code}")
            return False
    except Exception as e:
        print(f"SMS 2FA validation error: {e}")
        return False

# Main function to test the implementation
def main():
    print("=== iCloud MobileMe Login Test ===")
    
    # Test anisette server
    try:
        resp = requests.get(ANISETTE_URL, timeout=5)
        if resp.status_code != 200:
            print(f"Anisette server error: {resp.status_code}")
            return
        print("Anisette server is working")
    except Exception as e:
        print(f"Cannot connect to anisette server: {e}")
        return
    
    username = input("Apple ID: ").strip()
    if not username or "@" not in username:
        print("Please enter a valid Apple ID")
        return
    
    password = getpass("Password: ")
    if not password:
        print("Password cannot be empty")
        return
    
    # Choose 2FA method
    second_factor = input("2FA method (sms/trusted_device) [trusted_device]: ").strip() or "trusted_device"
    
    try:
        print(f"\nStarting authentication process...")
        result = icloud_login_mobileme(username, password, second_factor)
        
        if result:
            print("\n=== SUCCESS ===")
            print("MobileMe login successful!")
            
            # Save result
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"mobileme_result_{timestamp}.json"
            
            # Convert any bytes to strings for JSON serialization
            def serialize_bytes(obj):
                if isinstance(obj, bytes):
                    return base64.b64encode(obj).decode()
                elif isinstance(obj, dict):
                    return {k: serialize_bytes(v) for k, v in obj.items()}
                elif isinstance(obj, list):
                    return [serialize_bytes(v) for v in obj]
                return obj
            
            serializable_result = serialize_bytes(result)
            
            with open(filename, 'w') as f:
                json.dump(serializable_result, f, indent=2, default=str)
            
            print(f"Result saved to: {filename}")
            
            # Print some key information
            if isinstance(result, dict):
                print(f"\nResult keys: {list(result.keys())}")
                
                # Look for device information
                if 'devices' in result:
                    devices = result['devices']
                    print(f"Found {len(devices)} devices")
                    for i, device in enumerate(devices, 1):
                        name = device.get('name', 'Unknown')
                        model = device.get('model', 'Unknown')
                        print(f"  {i}. {name} ({model})")
                else:
                    print("No 'devices' key in result")
        else:
            print("\n=== FAILED ===")
            print("MobileMe login failed")
            
    except Exception as e:
        print(f"\nError during authentication: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()