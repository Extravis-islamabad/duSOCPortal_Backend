import base64
import hashlib
import hmac
import json
import time
import urllib.parse

import requests

base_url = "https://du.cyware.com/api/"  # nosec
access_id = "a78b2121-087c-497e-92d0-ba26896b8622" # nosec
secret_key = "c2400e30-6380-4f1d-948f-322e3f59c9e3"# nosec

expiration_margin_time = 20  # seconds

# Just for formatting
padding_length = 100
padding_design_char = "-"
tab_width = 25


class CywareTest:
    # Credentials to access CSAP open API
    @staticmethod
    def signature(access_id: str, secret_key: str, expires: int) -> str:
        """
        Computes and returns the API request signature.
        """
        to_sign = f"{access_id}\n{expires}"
        hashed = hmac.new(
            secret_key.encode("utf-8"), to_sign.encode("utf-8"), hashlib.sha1
        )
        return base64.b64encode(hashed.digest()).decode("utf-8")

    @staticmethod
    def expiry_time(margin: int = expiration_margin_time) -> int:
        """
        Returns the expiration timestamp with specified margin.
        """
        return int(time.time() + margin)

    @staticmethod
    def query(
        access_id: str,
        secret_key: str,
        expiration_margin_time: int,
        method: str,
        endpoint: str,
        data=None,
        headers=None,
        params=None,
    ):
        if headers is None:
            headers = {}
        if params is None:
            params = {}

        expires = CywareTest.expiry_time(expiration_margin_time)
        signature_value = CywareTest.signature(access_id, secret_key, expires)
        params["Expires"] = expires
        params["AccessID"] = access_id
        params["Signature"] = signature_value

        url = f"{base_url}{endpoint}?" + urllib.parse.urlencode(params, doseq=True)

        print(
            "Using python-requests module".center(padding_length, padding_design_char)
        )
        print("REQUEST DATA".center(padding_length, padding_design_char))
        request_data_dict = {
            "Method": method,
            "Params": params,
            "Header": headers,
            "Payload": data,
            "URL": url,
        }
        for key, val in request_data_dict.items():
            print("{:<{width}}{}".format(f"{key}:", val, width=tab_width))

        response = requests.request(method, url, headers=headers, json=data)

        print("RESPONSE DATA".center(padding_length, padding_design_char))
        print(
            "{:<{width}}{}".format(
                "Status-code:", response.status_code, width=tab_width
            )
        )
        print("{:<{width}}".format("Data:", width=tab_width))
        try:
            parsed = response.json()
            print(json.dumps(parsed, indent=2, ensure_ascii=False))
        except ValueError:
            print(response.text)
        return response

    @staticmethod
    def test_connectivity():
        """
        Calls the test_connectivity endpoint of the CSAP API.
        """
        print("Test Connectivity".center(padding_length, padding_design_char))
        endpoint = "csap/v1/test_connectivity/"
        method_type = "GET"
        CywareTest.query(
            access_id, secret_key, expiration_margin_time, method_type, endpoint
        )

    def get_list_alert():
        """
        Calls the test_connectivity endpoint of the CSAP API.
        """
        print("List Alert".center(padding_length, padding_design_char))
        endpoint = "csap/v1/list_alert/"
        method_type = "GET"
        CywareTest.query(
            access_id, secret_key, expiration_margin_time, method_type, endpoint
        )
