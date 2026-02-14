import time
import pathlib
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA512


import urllib.parse
import io
import base64
import datetime
import email.utils
import json
import urllib3

import requests

from urllib.parse import urlparse
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from .base import Plugin

class Duo(Plugin):
    def __init__(self, *args, **kwargs):
        self.host = None
        self.code = None
        
        super().__init__(*args, **kwargs)

    def import_key(self, keyfile):
        print(f"Importing key from {keyfile}")
        if issubclass(type(keyfile), io.IOBase):
            self.pubkey = RSA.import_key(keyfile.read())
        else:
            try:
                self.pubkey = RSA.import_key(keyfile)
            except ValueError:
                with open(keyfile, "rb") as f:
                    self.pubkey = RSA.import_key(f.read())


    def read_code(self, code):
        code, host = map(lambda x: x.strip("<>"), code.split("-"))
        missing_padding = len(host) % 4
        if missing_padding:
            host += '=' * (4 - missing_padding)
        self.code = code
        self.host = base64.decodebytes(host.encode("ascii")).decode('ascii')

    def import_response(self, response):
        print(f"Importing response from {response}")
        if type(response) is str:
            with open(response, "r") as f:
                response = json.load(f)
        if "response" in response:
            response = response["response"]
        self.info = response
        if self.host and ("host" not in self.info or not self.info["host"]):
            self.info["host"] = self.host
        elif not self.host and ("host" in self.info and self.info["host"]):
            self.host = self.info["host"]
        self.akey = response["akey"]
        self.pkey = response["pkey"]


    def generate_signature(self, method, path, time, data):
        message = (time + "\n" + method + "\n" + self.host.lower() + "\n" +
                   path + '\n' + urllib.parse.urlencode(data)).encode('ascii')

        h = SHA512.new(message)
        signature = pkcs1_15.new(self.pubkey).sign(h)
        auth = ("Basic "+base64.b64encode((self.pkey + ":" +
                base64.b64encode(signature).decode('ascii')).encode('ascii')).decode('ascii'))
        return auth

    def get_transactions(self):
        dt = datetime.datetime.utcnow()
        time = email.utils.format_datetime(dt)
        path = "/push/v2/device/transactions"
        data = {"akey": self.akey, "fips_status": "1",
                "hsm_status": "true", "pkpush": "rsa-sha512"}

        signature = self.generate_signature("GET", path, time, data)
        r = requests.get(f"https://{self.host}{path}", params=data, verify=False, headers={
                         "Authorization": signature, "x-duo-date": time, "host": self.host})

        return r.json()

    def reply_transaction(self, transactionid, answer):
        dt = datetime.datetime.utcnow()
        time = email.utils.format_datetime(dt)
        path = "/push/v2/device/transactions/"+transactionid
        data = {"akey": self.akey, "answer": answer, "fips_status": "1",
                "hsm_status": "true", "pkpush": "rsa-sha512"}

        signature = self.generate_signature("POST", path, time, data)
        r = requests.post(f"https://{self.host}{path}", data=data, verify=False, headers={
                          "Authorization": signature, "x-duo-date": time, "host": self.host, "txId": transactionid})

        return r.json()

    def register(self, token):
        dt = datetime.datetime.utcnow()
        time = email.utils.format_datetime(dt)
        path = "/push/v2/device/registration"
        data = {"akey": self.akey, "token": token}

        signature = self.generate_signature("POST", path, time, data)
        r = requests.post(f"https://{self.host}{path}", data=data, verify=False, headers={
                          "Authorization": signature, "x-duo-date": time, "host": self.host})
    def device_info(self):
        dt = datetime.datetime.utcnow()
        time = email.utils.format_datetime(dt)
        path = "/push/v2/device/info"
        data = {"akey": self.akey, "fips_status": "1",
                "hsm_status": "true", "pkpush": "rsa-sha512"}

        signature = self.generate_signature("GET", path, time, data)
        r = requests.get(f"https://{self.host}{path}", params=data, verify=False, headers={
                         "Authorization": signature, "x-duo-date": time, "host": self.host})
        return r.json()
