"""plugins/auth.py

Functions related to handling and checking authentication.
"""

import pyotp
import re
import requests
import json
import subprocess
import time
import sys
import urllib3
from bs4 import BeautifulSoup

from .base import Plugin
from urllib.parse import urlparse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class Auth(Plugin):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for plugin in ['Api', 'Db', 'Users', 'Duo']:
            setattr(self,
                    plugin.lower(),
                    self.registry.get(plugin)(self.state))
        try:
            with open(f"{self.state.config_dir}/duo.json") as fp:
                duo_config = json.load(fp)
                self.DUO_POLL_INTERVAL = 2  # seconds
                self.MAX_RETRIES = 10

                self.DEVICE_NAME = duo_config.get("device_name", "phone1")
                self.DEVICE_KEY = duo_config.get("device_key", "DA9KXXXXXXX052UWB")
        except Exception as e:
            print(f"Error loading duo.json: {e}")
            sys.exit(1)

    def build_otp(self):
        """Generate and return a OTP."""
        totp = pyotp.TOTP(self.db.otp_secret)
        totp.digits = 7
        totp.interval = 10
        totp.issuer = 'synack'
        return totp.now()

    def get_grant_token(self):
        def is_json(response):
            try:
                response.json()
                return True
            except ValueError:
                return False

        # Function to exit on error with a message
        def exit_on_error(message):
            print(message)
            sys.exit(1)

        # Initialize a session with a cookie jar
        session = requests.Session()
        session.cookies = requests.cookies.RequestsCookieJar()

        # Custom headers
        custom_headers = {
            "User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br"
        }

        # Step 1: GET request to login.synack.com to fetch CSRF token
        try:
            response = session.get('https://login.synack.com', headers=custom_headers, verify=False)
            if response.status_code != 200:
                exit_on_error("Failed to fetch CSRF token")
            soup = BeautifulSoup(response.text, 'html.parser')
            csrf_token = soup.find('meta', {'name': 'csrf-token'})['content']
        except Exception as e:
            exit_on_error(f"Error during fetching CSRF token: {e}")
        
        # Step 2: POST request to /api/authenticate with credentials
        for attempt in range(self.MAX_RETRIES):
            try:
                login_url = 'https://login.synack.com/api/authenticate'
                login_data = {"email": self.db.email, "password": self.db.password}
                headers = {'X-Csrf-Token': csrf_token}
                response = session.post(login_url, json=login_data, headers=headers)
                
                if response.status_code == 200 and is_json(response):
                    response_data = response.json()
                    duo_auth_url = response_data.get('duo_auth_url')
                    if duo_auth_url:
                        print("[!] Login successful on attempt {}".format(attempt + 1))
                        break  # Successful login, break out of the loop
                    else:
                        exit_on_error("Duo Auth URL missing in response")
                else:
                    print(f"Login attempt {attempt + 1} failed, status code: {response.status_code}, retrying...")
                    if attempt == self.MAX_RETRIES - 1:
                        exit_on_error("Login failed after maximum retries")

            except Exception as e:
                print(f"Login attempt {attempt + 1} failed with error: {e}")
                if attempt == self.MAX_RETRIES - 1:
                    exit_on_error("Error during login after maximum retries: {e}")



        # Step 3: GET request to Duo Auth URL (Request 1 to DUO)
        try:
            response = session.get(duo_auth_url, headers=custom_headers, verify=False)
            if response.status_code != 200:
                exit_on_error("Failed to GET Duo Auth URL")
            session.cookies.update(response.cookies)  # Update cookie jar

            # Handle redirection
            redirect_url = response.history[-1].headers['Location']
            redirect_full_url = f"https://api-64d8e0cf.duosecurity.com{redirect_url}"
            response = session.get(redirect_full_url, headers=custom_headers, verify=False)
            if response.status_code != 200:
                exit_on_error("Failed to follow redirect URL")
            session.cookies.update(response.cookies)  # Update cookie jar
        except Exception as e:
            exit_on_error(f"Error during Duo Auth process: {e}")

        # Extract XSRF token from the script tag in the HTML response
        try:
            soup = BeautifulSoup(response.text, 'html.parser')
            script_tag = soup.find('script', {'id': 'base-data'})
            json_data = json.loads(script_tag.text)
            xsrf_token = json_data['xsrf_token']
        except Exception as e:
            exit_on_error(f"Error extracting XSRF token: {e}")

        # Extract 'sid' and 'tx' from URL
        try:
            sid = response.url.split('sid=')[1].split('&')[0]
            tx = redirect_url.split('&tx=')[1].split('&')[0]
        except Exception as e:
            exit_on_error(f"Error extracting 'sid' and 'tx': {e}")
        # Step 4: POST Request to Duo with XSRF Token and extracted data
        try:
            base_url = "https://api-64d8e0cf.duosecurity.com/frame/frameless/v4/auth"
            post_url = f"{base_url}?sid={sid}&tx={tx}"
            post_data = {
            'tx': tx,
            'parent': 'None',
            '_xsrf': xsrf_token,
            'java_version': '',
            'flash_version': '',
            'screen_resolution_width': '1920',
            'screen_resolution_height': '1080',
            'color_depth': '24',
            'ch_ua_error': '',
            'client_hints': '',
            'is_cef_browser': 'false',
            'is_ipad_os': 'false',
            'is_ie_compatibility_mode': '',
            'is_user_verifying_platform_authenticator_available': 'false',
            'user_verifying_platform_authenticator_available_error': '',
            'acting_ie_version': '',
            'react_support': 'true',
            'react_support_error_message': '',
            }
            cookies_header = {'Cookie': '; '.join([f'{name}={value}' for name, value in session.cookies.items()])}
            response = session.post(post_url, data=post_data, headers={**custom_headers, **cookies_header})
            if response.status_code != 200:
                exit_on_error("Failed to POST data to Duo")
            session.cookies.update(response.cookies)
        except Exception as e:
            exit_on_error(f"Error during POST request to Duo: {e}")

        # Step 5: Follow Redirects and Perform Health Check
        try:
            health_check_urls = [
                f'https://api-64d8e0cf.duosecurity.com/frame/v4/preauth/healthcheck?sid={sid}',
                f'https://api-64d8e0cf.duosecurity.com/frame/v4/preauth/healthcheck/data?sid={sid}',
                f'https://api-64d8e0cf.duosecurity.com/frame/v4/return?sid={sid}'
            ]
            for url in health_check_urls:
                response = session.get(url, verify=False)
                if response.status_code != 200:
                    exit_on_error(f"Health check failed for URL: {url}")
                session.cookies.update(response.cookies)
        except Exception as e:
            exit_on_error(f"Error during health check: {e}")

        # Step 5.1: POST Request again to Duo with XSRF Token and extracted data
        try:
            base_url = "https://api-64d8e0cf.duosecurity.com/frame/frameless/v4/auth"
            post_url = f"{base_url}?sid={sid}&tx={tx}"
            post_data = {
            'tx': tx,
            'parent': 'None',
            '_xsrf': xsrf_token,
            'java_version': '',
            'flash_version': '',
            'screen_resolution_width': '1920',
            'screen_resolution_height': '1080',
            'color_depth': '24',
            'ch_ua_error': '',
            'client_hints': '',
            'is_cef_browser': 'false',
            'is_ipad_os': 'false',
            'is_ie_compatibility_mode': '',
            'is_user_verifying_platform_authenticator_available': 'false',
            'user_verifying_platform_authenticator_available_error': '',
            'acting_ie_version': '',
            'react_support': 'true',
            'react_support_error_message': '',
            }
            cookies_header = {'Cookie': '; '.join([f'{name}={value}' for name, value in session.cookies.items()])}
            response = session.post(post_url, data=post_data, headers={**custom_headers, **cookies_header})
            if response.status_code != 200:
                exit_on_error("Failed to POST data to Duo for step 5.1")
            session.cookies.update(response.cookies)
        except Exception as e:
            exit_on_error(f"Error during POST request to Duo: {e}")

        # Step 6: Setup Device Prompt
        try:
            prompt_urls = [
                f'https://api-64d8e0cf.duosecurity.com/frame/v4/auth/prompt?sid={sid}',
                f'https://api-64d8e0cf.duosecurity.com/frame/v4/auth/prompt/data?sid={sid}'
            ]
            for url in prompt_urls:
                response = session.get(url, verify=False)
                if response.status_code != 200:
                    exit_on_error(f"Failed to setup device prompt for URL: {url}")
        except Exception as e:
            exit_on_error(f"Error during device prompt setup: {e}")
        # Step 7: Sending POST to Duo for Device Selection and Duo Push
        self.duo.import_key(f"{self.state.config_dir}/key.pem")
        self.duo.import_response(f"{self.state.config_dir}/response.json")

        try:
            prompt_url = 'https://api-64d8e0cf.duosecurity.com/frame/v4/prompt'
            prompt_data = {
                'device': self.DEVICE_NAME,  # Default device
                'factor': 'Duo Push',
                'postAuthDestination': 'OIDC_EXIT',
                'browser_features': '{"touch_supported":false, "platform_authenticator_status":"unavailable", "webauthn_supported":true}',
                'sid': sid
            }
            prompt_response = session.post(prompt_url, data=prompt_data)
            if prompt_response.status_code != 200 or not is_json(prompt_response):
                exit_on_error("Failed to send POST to Duo for device selection")
            txid = prompt_response.json()['response']['txid']
            approved = False
            
            while not approved:
                try:
                    r = self.duo.get_transactions()
                except requests.exceptions.ConnectionError:
                    print("Connection Error")
                    time.sleep(5)
                    continue

                t = r["response"]["transactions"]
                print("Checking for transactions")
                if len(t):
                    for tx in t:
                        self.duo.reply_transaction(tx["urgid"], 'approve')
                    approved = True
                else:
                    print("No transactions")

                time.sleep(10)

        except Exception as e:
            exit_on_error(f"Error during Duo device selection POST: {e}")

        # Step 8: Polling for Duo Push Status
        try:
            while True:
                status_data = {'txid': txid, 'sid': sid}
                status_response = session.post('https://api-64d8e0cf.duosecurity.com/frame/v4/status', data=status_data)
                if not status_response.status_code == 200 or not is_json(status_response):
                    exit_on_error("Failed to poll Duo Push status")
                status_response_data = status_response.json()
                if status_response_data['response']['status_code'] == 'allow' and status_response_data['response']["result"]=="SUCCESS":
                    print("Duo authentication successful.")
                    break
                elif status_response_data['response']['status_code'] == 'timeout':
                    print("Device failed to respond.")
                    # Handling a timeout scenario without switching to a backup device.
                    # Additional actions can be added here.
                    break

                time.sleep(DUO_POLL_INTERVAL)
        except Exception as e:
            exit_on_error(f"Error during polling for Duo Push status: {e}")


        # Step 9: Finalizing Authentication with Synack
        try:
            final_auth_url = 'https://api-64d8e0cf.duosecurity.com/frame/v4/oidc/exit'
            final_auth_data = {
                'sid': sid,
                'txid': txid,
                'factor': 'Duo Push',
                'device_key': self.DEVICE_KEY,
                '_xsrf': xsrf_token,
                'dampen_choice': 'false'
            }
            final_auth_response = session.post(final_auth_url, data=final_auth_data, verify=False)
            if final_auth_response.status_code != 200:
                print("Failed to finalize authentication with Synack")
                final_auth_response = session.post(final_auth_url, data=final_auth_data, verify=False)
        except Exception as e:
            exit_on_error(f"Error during final authentication with Synack: {e}")


        # Step 10: Final Redirect to Synack with Grant Token
        try:
            final_response = session.get(final_auth_response.url, verify=False)
            if final_response.status_code != 200:
                exit_on_error("Failed during final redirect to Synack")
            grant_token = final_response.url.split('grant_token=')[1]
            return grant_token
        except Exception as e:
            exit_on_error(f"Error during final redirect: {e}")

    def get_api_token(self):
        """Log in to get a new API token."""
        if self.users.get_profile():
            return self.db.api_token

        grant_token = self.get_grant_token()

        if grant_token:
            url = 'https://platform.synack.com/'
            headers = {
                'X-Requested-With': 'XMLHttpRequest'
            }
            query = {
                "grant_token": grant_token
            }
            res = self.api.request('GET',
                                   url + 'token',
                                   headers=headers,
                                   query=query)
            if res.status_code == 200:
                j = res.json()
                self.db.api_token = j.get('access_token')
                return j.get('access_token')

    def get_notifications_token(self):
        """Request a new Notifications Token"""
        res = self.api.request('GET', 'users/notifications_token')
        if res.status_code == 200:
            j = res.json()
            self.db.notifications_token = j['token']
            return j['token']

