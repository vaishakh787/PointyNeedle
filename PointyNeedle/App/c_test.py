#!/usr/bin/env python3
"""
Working iCloud Authentication Script - Based on JJTech0130's implementation
Uses the correct GSA protocol format that Apple expects
"""

import uuid
import json
import base64
import time
from getpass import getpass
from datetime import datetime, timezone
import locale
import requests
import plistlib as plist
import srp._pysrp as srp
import hashlib
import hmac
import binascii
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import urllib3

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---------------------- Configuration ----------------------
ANISETTE_URL = "http://127.0.0.1:6969"
USER_ID = str(uuid.uuid4()).upper()
DEVICE_ID = str(uuid.uuid4()).upper()

# Configure SRP properly
srp.rfc5054_enable()
srp.no_username_in_x()

class WorkingiCloudAuth:
    def __init__(self, anisette_url=ANISETTE_URL):
        self.anisette_url = anisette_url
        self.user_id = USER_ID
        self.device_id = DEVICE_ID
        self.session = requests.Session()
        self.session.verify = False
        
        # User agent and client info that Apple expects
        self.user_agent = "akd/1.0 CFNetwork/1408.0.4 Darwin/22.5.0"
        self.client_info = "<MacBookPro18,3> <Mac OS X;13.4.1;22F8> <com.apple.AOSKit/282 (com.apple.dt.Xcode/3594.4.19)>"
        
    def generate_anisette_headers(self):
        """Generate Anisette headers required for Apple authentication"""
        print(f"[anisette] Fetching headers from {self.anisette_url}...")
        try:
            response = self.session.get(self.anisette_url, timeout=10)
            response.raise_for_status()
            return response.json()
            
        except Exception as e:
            print(f"[anisette] Error fetching headers: {e}")
            raise
    
    def generate_meta_headers(self):
        """Generate meta headers for Apple requests"""
        return {
            "X-Apple-I-Client-Time": datetime.utcnow().replace(microsecond=0).isoformat() + "Z",
            "X-Apple-I-TimeZone": str(datetime.utcnow().astimezone().tzinfo),
            "loc": locale.getdefaultlocale()[0] or "en_US",
            "X-Apple-Locale": locale.getdefaultlocale()[0] or "en_US",
            "X-Apple-I-MD-RINFO": "17106176",
            "X-Apple-I-MD-LU": base64.b64encode(self.user_id.encode()).decode(),
            "X-Mme-Device-Id": self.device_id,
            "X-Apple-I-SRL-NO": "0",
        }
    
    def generate_cpd(self):
        """Generate CPD (Client Platform Data) for GSA requests"""
        print("[cpd] Generating client platform data...")
        
        cpd = {
            "bootstrap": True,
            "icscrec": True,
            "pbe": False,
            "prkgen": True,
            "svct": "iCloud",
        }
        
        # Add meta headers
        cpd.update(self.generate_meta_headers())
        
        # Add anisette headers
        anisette_data = self.generate_anisette_headers()
        cpd.update(anisette_data)
        
        print("[cpd] Client platform data generated successfully")
        return cpd
    
    def encrypt_password(self, password, salt, iterations, protocol):
        """Encrypt password using Apple's protocol - WORKING VERSION"""
        try:
            print(f"[crypto] Encrypting password with protocol: {protocol}")
            
            # First hash with SHA256
            p = hashlib.sha256(password.encode("utf-8")).digest()
            
            # For s2k_fo protocol, convert to hex string then back to bytes
            if protocol == "s2k_fo":
                p = p.hex().encode("utf-8")
            
            # Use the standard library PBKDF2 (this is the key fix!)
            return hashlib.pbkdf2_hmac("sha256", p, salt, iterations, 32)
            
        except Exception as e:
            print(f"[crypto] Error encrypting password: {e}")
            raise
    
    def create_session_key(self, usr, name):
        """Create session key for decryption"""
        try:
            session_key = usr.get_session_key()
            if session_key is None:
                raise Exception("No session key available")
            return hmac.new(session_key, name.encode(), hashlib.sha256).digest()
        except Exception as e:
            print(f"[crypto] Error creating session key: {e}")
            raise
    
    def decrypt_cbc(self, usr, data):
        """Decrypt CBC encrypted data - WORKING VERSION"""
        try:
            extra_data_key = self.create_session_key(usr, "extra data key:")
            extra_data_iv = self.create_session_key(usr, "extra data iv:")
            
            # Get only the first 16 bytes of the iv
            extra_data_iv = extra_data_iv[:16]
            
            # Decrypt with AES CBC
            cipher = Cipher(algorithms.AES(extra_data_key), modes.CBC(extra_data_iv))
            decryptor = cipher.decryptor()
            data = decryptor.update(data) + decryptor.finalize()
            
            # Remove PKCS#7 padding - FIXED
            unpadder = padding.PKCS7(128).unpadder()
            return unpadder.update(data) + unpadder.finalize()
            
        except Exception as e:
            print(f"[crypto] Error decrypting data: {e}")
            raise
    
    def gsa_request(self, parameters, debug=True):
        """Make GSA request with correct format"""
        
        # Build request body in the correct format
        body = {
            "Header": {"Version": "1.0.1"},
            "Request": {"cpd": self.generate_cpd()},
        }
        body["Request"].update(parameters)
        
        headers = {
            "Content-Type": "text/x-xml-plist",
            "Accept": "*/*",
            "User-Agent": self.user_agent,
            "X-MMe-Client-Info": self.client_info,
        }
        
        try:
            if debug:
                print(f"[gsa] Request operation: {parameters.get('o', 'unknown')}")
            
            print("[gsa] Sending request to Apple GSA service...")
            
            response = self.session.post(
                "https://gsa.apple.com/grandslam/GsService2",
                headers=headers,
                data=plist.dumps(body),
                timeout=30
            )
            
            print(f"[gsa] Response status: {response.status_code}")
            
            if response.status_code == 404:
                print("[gsa] GSA endpoint returned 404 - Apple may have changed their API")
                raise Exception("GSA endpoint not found")
            
            response.raise_for_status()
            
            # Parse plist response
            response_data = plist.loads(response.content)
            
            if debug and "Response" in response_data:
                resp_keys = list(response_data["Response"].keys())
                print(f"[gsa] Response keys: {resp_keys}")
            
            if "Response" not in response_data:
                raise Exception("Invalid response format from GSA service")
                
            return response_data["Response"]
            
        except Exception as e:
            print(f"[gsa] Request failed: {e}")
            if hasattr(e, 'response') and hasattr(e.response, 'content'):
                try:
                    # Try to parse error response
                    error_data = plist.loads(e.response.content)
                    print(f"[gsa] Error response: {error_data}")
                except:
                    print(f"[gsa] Raw response: {e.response.content[:500]}")
            raise
    
    def handle_2fa_trusted_device(self, dsid, idms_token):
        """Handle trusted device 2FA"""
        print("[2fa] Triggering trusted device authentication...")
        
        identity_token = base64.b64encode(f"{dsid}:{idms_token}".encode()).decode()
        
        headers = {
            "Content-Type": "text/x-xml-plist",
            "User-Agent": "Xcode",
            "Accept": "text/x-xml-plist",
            "Accept-Language": "en-us",
            "X-Apple-Identity-Token": identity_token,
            "X-Apple-App-Info": "com.apple.gs.xcode.auth",
            "X-Xcode-Version": "11.2 (11B41)",
            "X-Mme-Client-Info": self.client_info,
        }
        
        # Add meta headers
        headers.update(self.generate_meta_headers())
        
        # Add anisette headers
        anisette_data = self.generate_anisette_headers()
        headers.update(anisette_data)
        
        try:
            # Trigger 2FA prompt
            self.session.get(
                "https://gsa.apple.com/auth/verify/trusteddevice",
                headers=headers,
                timeout=10
            )
            
            # Get 2FA code from user
            code = input("Enter the 6-digit verification code from your trusted device: ").strip()
            
            if not code or len(code) != 6 or not code.isdigit():
                print("[2fa] Invalid code format")
                return False
            
            # Submit 2FA code
            headers["security-code"] = code
            
            response = self.session.get(
                "https://gsa.apple.com/grandslam/GsService2/validate",
                headers=headers,
                timeout=10
            )
            
            if response.ok:
                print("[2fa] Trusted device authentication successful")
                return True
            else:
                print("[2fa] Trusted device authentication failed")
                return False
                
        except Exception as e:
            print(f"[2fa] Trusted device authentication error: {e}")
            return False
    
    def authenticate(self, apple_id, password):
        """Main authentication method - WORKING VERSION"""
        try:
            print(f"[icloud] Starting authentication for {apple_id}")
            
            # Initialize SRP user
            usr = srp.User(apple_id, bytes(), hash_alg=srp.SHA256, ng_type=srp.NG_2048)
            _, A = usr.start_authentication()
            
            print(f"[srp] SRP initialized successfully")
            
            # Initial authentication request
            response = self.gsa_request({
                "A2k": A,
                "ps": ["s2k", "s2k_fo"],
                "u": apple_id,
                "o": "init"
            })
            
            # Validate response
            if "sp" not in response:
                print(f"[icloud] Failed to authenticate: {response}")
                return None
            
            if response["sp"] not in ["s2k", "s2k_fo"]:
                print(f"[icloud] Unsupported protocol: {response['sp']}")
                return None
            
            print(f"[icloud] Using protocol: {response['sp']}")
            
            # Extract parameters
            protocol = response["sp"]
            salt = response["s"]
            B = response["B"]
            c = response["c"]
            iterations = response["i"]
            
            print(f"[srp] Salt length: {len(salt)}, B length: {len(B)}, iterations: {iterations}")
            
            # Encrypt password - this is the critical fix
            usr.p = self.encrypt_password(password, salt, iterations, protocol)
            
            # Process SRP challenge
            M = usr.process_challenge(salt, B)
            
            if M is None:
                print("[srp] Failed to process SRP challenge")
                return None
            
            print("[srp] SRP challenge processed successfully")
            
            # Complete authentication
            response = self.gsa_request({
                "c": c,
                "M1": M,
                "u": apple_id,
                "o": "complete"
            })
            
            # Check for successful authentication
            if "M2" not in response:
                print("[icloud] M2 not in response - checking for 2FA or errors...")
                
                # Check for 2FA requirement
                if "Status" in response and "au" in response["Status"]:
                    print("[2fa] Two-factor authentication required")
                    
                    # Extract tokens needed for 2FA
                    dsid = response.get("dsid")
                    idms_token = response.get("Status", {}).get("idmsToken")
                    
                    if dsid and idms_token:
                        if self.handle_2fa_trusted_device(dsid, idms_token):
                            # Re-attempt authentication after 2FA
                            print("[icloud] Re-attempting authentication after 2FA...")
                            # In a full implementation, you'd need to restart the auth flow
                            # For now, we'll indicate partial success
                            return {
                                "user_id": apple_id,
                                "authenticated": "2fa_completed",
                                "dsid": dsid,
                                "message": "2FA completed, full auth requires restart"
                            }
                        else:
                            return None
                    else:
                        print("[2fa] Missing required tokens for 2FA")
                        return None
                else:
                    print("[icloud] Authentication failed - invalid credentials")
                    return None
            
            # Verify SRP session
            print("[icloud] Verifying SRP session...")
            usr.verify_session(response["M2"])
            
            if not usr.authenticated():
                print("[icloud] SRP session verification failed")
                return None
            
            print("[icloud] SRP session verified successfully")
            
            # Decrypt service data
            if "spd" not in response:
                print("[icloud] No service data in response")
                return None
            
            print("[icloud] Decrypting service data...")
            try:
                encrypted_data = response["spd"]
                decrypted_data = self.decrypt_cbc(usr, encrypted_data)
                
                # Parse decrypted plist - FIXED format
                service_data = plist.loads(decrypted_data, fmt=plist.FMT_XML)
                
                print("[icloud] Service data decrypted successfully")
                
            except Exception as e:
                print(f"[icloud] Failed to decrypt service data: {e}")
                # Try without XML header
                try:
                    service_data = plist.loads(decrypted_data)
                    print("[icloud] Service data decrypted with fallback method")
                except:
                    return None
            
            print("[icloud] ✅ Authentication completed successfully!")
            
            return {
                "user_id": apple_id,
                "authenticated": True,
                "session_token": usr.get_session_key().hex(),
                "services": service_data,
                "dsid": service_data.get("dsid"),
                "raw_response": response
            }
            
        except Exception as e:
            print(f"[icloud] Authentication error: {e}")
            import traceback
            traceback.print_exc()
            return None

def test_anisette_server(url):
    """Test if Anisette server is working properly"""
    try:
        print(f"[test] Testing Anisette server at {url}...")
        response = requests.get(url, timeout=5)
        
        if response.status_code != 200:
            print(f"[test] Server returned status code: {response.status_code}")
            return False
        
        data = response.json()
        required_headers = ["X-Apple-I-MD", "X-Apple-I-MD-M"]
        
        missing_headers = [h for h in required_headers if not data.get(h)]
        if missing_headers:
            print(f"[test] Missing required headers: {missing_headers}")
            return False
        
        print("[test] ✅ Anisette server is working correctly")
        return True
        
    except Exception as e:
        print(f"[test] Anisette server test failed: {e}")
        return False

def main():
    """Main function"""
    print("=== Working iCloud Authentication Tool ===")
    print("Based on JJTech0130's GSA implementation\n")
    
    # Test Anisette server
    if not test_anisette_server(ANISETTE_URL):
        print(f"\n[error] Anisette server at {ANISETTE_URL} is not working properly")
        print("[error] Please ensure the Anisette server is running:")
        print("[error] docker run -d --name anisette -p 6969:6969 dadoum/anisette-v3-server")
        return
    
    # Get credentials
    apple_id = input("Apple ID (email): ").strip()
    if not apple_id or "@" not in apple_id:
        print("[error] Please enter a valid Apple ID email address")
        return
    
    password = getpass("Password: ")
    if not password:
        print("[error] Password cannot be empty")
        return
    
    print(f"\n[info] Starting authentication process...")
    
    # Authenticate
    auth = WorkingiCloudAuth()
    result = auth.authenticate(apple_id, password)
    
    if result:
        print(f"\n🎉 Authentication result for {apple_id}:")
        print(f"📱 Status: {result.get('authenticated', 'Unknown')}")
        
        if result.get('dsid'):
            print(f"👤 DSID: {result['dsid']}")
        
        if result.get('session_token'):
            print(f"🔑 Session token: {result['session_token']}...")
        
        if result.get('services'):
            services = list(result['services'].keys())
            print(f"🔧 Available services ({len(services)}): {', '.join(services[:5])}")
            if len(services) > 5:
                print(f"    ... and {len(services) - 5} more")
        
        if result.get('message'):
            print(f"ℹ️  Note: {result['message']}")
        
        # Save result to file
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"icloud_auth_{timestamp}.json"
        
        # Prepare data for saving
        save_data = {
            "user_id": result["user_id"],
            "authenticated": result["authenticated"],
            "dsid": result.get("dsid"),
            "services": result.get("services"),
            "timestamp": timestamp,
        }
        
        try:
            with open(filename, 'w') as f:
                json.dump(save_data, f, indent=2, default=str)
            print(f"💾 Authentication data saved to: {filename}")
        except Exception as e:
            print(f"⚠️  Could not save to file: {e}")
        
    else:
        print("\n❌ Authentication failed!")
        print("\nTroubleshooting checklist:")
        print("✓ Verify your Apple ID and password are correct")
        print("✓ Make sure 2FA is enabled on your Apple account")
        print("✓ Try logging into iCloud.com first to verify credentials")
        print("✓ Ensure the Anisette server is running properly")
        print("✓ Check your network connection")
        

if __name__ == "__main__":
    main()