import base64
import hashlib
import json
import os
from typing import List
from urllib.parse import urlencode

import httpx
import jwt
import requests
from fastapi import HTTPException
from pydantic import BaseModel

from api.models.APIModels import OAuth


class GoogleAppDetails(BaseModel):
    client_id: str
    client_secret: str
    redirect_uris: List[str]
    token_uri: str
    revoke_uri: str
    token_info_uri: str
    auth_uri: str
    scopes: str


class GoogleProviderManager:

    def __init__(self, google_oauth_path):
        self.oauth_details: GoogleAppDetails = self.__gather_oauth_details(google_oauth_path)

    def get_auth_url(self, code_challenge: str, session_data: str) -> str:
        encoded_url = urlencode({
            "client_id": self.oauth_details.client_id,
            "redirect_uri": self.oauth_details.redirect_uris[0],
            "response_type": "code",
            "scope": self.oauth_details.scopes,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "access_type": "offline",
            "prompt": "consent",
            "state": session_data
        })
        return f"{self.oauth_details.auth_uri}?" + encoded_url

    async def validate_user(self, auth_code: str, code_verifier):
        token_data = {
            "code": auth_code,
            "client_id": self.oauth_details.client_id,
            "client_secret": self.oauth_details.client_secret,
            "redirect_uri": self.oauth_details.redirect_uris[0],
            "grant_type": "authorization_code",
            "code_verifier": code_verifier
        }

        async with httpx.AsyncClient() as client:
            token_response = await client.post(self.oauth_details.token_uri, data=token_data)
            response_data = token_response.json()

        if "error" in response_data:
            raise Exception(response_data["error_description"])

        id_token = response_data["id_token"]
        access_token = response_data["access_token"]
        refresh_token = response_data["refresh_token"] if response_data["refresh_token"] else None
        user_details = self.__decode_jwt(id_token)
        if not user_details:
            return None

        return user_details, access_token, refresh_token

    def handle_login(self, oauth: OAuth):
        access_token = oauth.access_token
        refresh_token = oauth.refresh_token

        if not access_token and not refresh_token:
            raise Exception("Access token or refresh token is required")

        validate_access_token = self.verify_access_token(access_token)

        if not validate_access_token:
            if not refresh_token:
                raise Exception("Access token invalid, please provide a refresh token")

            access_token = self.__refresh_access_token(refresh_token)
            validate_access_token = self.verify_access_token(access_token)

        return access_token, validate_access_token

    def handle_logout(self, access_token) -> bool:
        response = requests.post(self.oauth_details.revoke_uri, data={"token": access_token},
                                 headers={"Content-Type": "application/x-www-form-urlencoded"})
        return response.json()

    def __refresh_access_token(self, refresh_token):
        payload = {
            "client_id": self.oauth_details.client_id,
            "client_secret": self.oauth_details.client_secret,
            "refresh_token": refresh_token,
            "grant_type": "refresh_token"
        }

        response = requests.post(self.oauth_details.token_uri, data=payload)
        response_data = response.json()

        if response.status_code != 200:
            raise Exception("Error while refreshing access token, please provide a valid refresh token")
        access_token = response_data["access_token"]

        return access_token

    @staticmethod
    def generate_pkce():
        code_verifier = base64.urlsafe_b64encode(os.urandom(40)).rstrip(b'=').decode('utf-8')
        code_challenge = base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode('utf-8'))
                                                  .digest()).rstrip(b'=').decode('utf-8')
        return code_verifier, code_challenge

    @staticmethod
    def __gather_oauth_details(google_oauth_path) -> GoogleAppDetails:
        with open(google_oauth_path, 'r') as f:
            oauth_data = json.load(f)
            oauth_data = oauth_data["web"]
        return GoogleAppDetails(**oauth_data)

    def verify_auth_token(self, authorization_token: str):
        print(authorization_token)
        validate_access_token = requests.get(f"{self.oauth_details.token_info_uri}?access_token={authorization_token}")
        validity_result = validate_access_token.json()
        if validate_access_token.status_code != 200:
            raise HTTPException(status_code=401, detail="Invalid access token")

        return validity_result['sub']

    def verify_access_token(self, access_token):
        validate_access_token = requests.get(f"{self.oauth_details.token_info_uri}?access_token={access_token}")
        validity_result = validate_access_token.json()
        if validate_access_token.status_code != 200:
            return False

        return validity_result

    @staticmethod
    def __decode_jwt(token):
        decoded_token = jwt.decode(token, options={"verify_signature": False}, algorithms=["RS256", "HS256"])
        return decoded_token
