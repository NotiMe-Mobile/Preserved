import logging
import secrets
from datetime import datetime
import datetime as dt
from nanoid import generate

from fastapi import APIRouter, Request, HTTPException, Header
from starlette.responses import RedirectResponse

from databases.DBHandler import Users
from services.api.APIModels import OAuth


class AuthRouter(APIRouter):

    def __init__(self, cache_db_handler, google_provider_manager):
        super().__init__(prefix="/auth")
        self._cache_db_handler = cache_db_handler
        self._google_provider_manager = google_provider_manager
        self._endpoint_logger = logging.getLogger("ENDPOINT")
        self.add_auth_routes()

    def add_auth_routes(self):
        @self.get("/google/login", status_code=302, description="Redirects to google login page")
        def google_login(request: Request):
            """
            Handles the creation of the PKCE code verifier and challenge, then redirects to the Google login page
            while returning the same values.
            :param request: General request object
            :return: RedirectResponse to Google login page
            """
            code_verifier, code_challenge = self._google_provider_manager.generate_pkce()
            session_data = secrets.token_urlsafe(16)
            client_host = request.client.host
            self._endpoint_logger.info(f"[GOOGLE_LOGIN:{client_host}] Generated code_verifier: {code_verifier[:5]}...")

            # Setting is cache for retrieval in callback
            self._cache_db_handler.set_in_cache(f"code_verifier:{session_data}", code_verifier, 20)
            auth_url = self._google_provider_manager.get_auth_url(code_challenge, session_data)
            self._endpoint_logger.info(f"[GOOGLE_LOGIN:{client_host}] Redirecting to Google login page")
            return RedirectResponse(auth_url)

        @self.get("/google/callback", status_code=200, description="Handles google callback after authentication")
        async def google_callback(request: Request):
            """
            Handles the verification after the user has been authenticated with Google.
            Ensuring the authentication token is correct and verified successfully against Google.
            :param request: The general request object
            :return: Access Token of the user, Refresh Token, User details, and if the user is new or not
            """
            auth_code = request.query_params.get("code")
            session_data = request.query_params.get("state")

            self._endpoint_logger.info(f"[GOOGLE_CALLBACK:{request.client.host}] "
                                       f"Received auth_code: {auth_code[:5]}...")

            code_verifier = self._cache_db_handler.get_from_cache(f"code_verifier:{session_data}")

            if not code_verifier:
                self._endpoint_logger.info(f"[GOOGLE_CALLBACK:{request.client.host}] "
                                           f"Invalid session data: {session_data}")
                raise HTTPException(status_code=400, detail="Invalid request")

            try:
                user_details, access_token, refresh_token = await (self._google_provider_manager.
                                                                   validate_user(auth_code, code_verifier))
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))

            google_id = user_details["sub"]
            user_data = self._cache_db_handler.get_from_db(Users, {"google_id": google_id})
            if not user_data:
                self._endpoint_logger.info(f"[GOOGLE_CALLBACK:{request.client.host}] Creating new user in Database")
                user_data = {
                    "user_id": generate("0123456789", 12),
                    "google_id": google_id,
                    "email": user_details["email"],
                    "first_name": user_details["given_name"],
                    "last_name": user_details["family_name"],
                    "username": user_details["name"],
                    "avatar_url": user_details["picture"]
                }
                self._endpoint_logger.debug(f"[GOOGLE_CALLBACK:{request.client.host}] User Details: [{user_data}]")

                user_status = self._cache_db_handler.set_in_db(Users, user_data)
                if not user_status:
                    raise HTTPException(status_code=500, detail="Error in creating a user")

                new_user = True
                self._endpoint_logger.info(f"[GOOGLE_CALLBACK:{request.client.host}] Created new user in Database")
            else:
                new_user = False

                self._endpoint_logger.info(f"[GOOGLE_CALLBACK:{request.client.host}] Got user details from Database "
                                           f"with ID: [{google_id}]")

            user_data = self._cache_db_handler.get_data(key=f"user_details:{access_token}", model=Users,
                                                        query_params={"google_id": google_id}, ttl=3600)

            return {"access_token": access_token, "refresh_token": refresh_token,
                    "user_details": user_data, "new_user": new_user}

        @self.post("/login", status_code=200, description="Handles login request with OAuth token")
        def login(request: Request, oauth: OAuth, x_auth_token=Header("google")):
            """
            Handles the login request with the OAuth token and the token type.
            Currently only Google is supported.
            :param request: The request object
            :param oauth: The Authentication type (Access token, refresh token, etc...)
            :param x_auth_token: Authentication token type
            :return: User details if validated successfully
            """
            self._endpoint_logger.info(f"[LOGIN:{request.client.host}] Received request to login with "
                                       f"[{x_auth_token.upper()}]")
            try:
                if x_auth_token.lower() == "google":
                    access_token, validity_result = self._google_provider_manager.handle_login(oauth)
                else:
                    self._endpoint_logger.info(f"[LOGIN:{request.client.host}] Invalid token: {x_auth_token}, "
                                               f"not implemented")
                    raise HTTPException(status_code=501, detail="Not implemented yet...")
            except HTTPException as e:
                raise e
            except Exception as e:
                raise HTTPException(status_code=401, detail=str(e))

            google_id = validity_result["sub"]
            user_data = self._cache_db_handler.update_data(access_token,
                                                           Users,
                                                           {"google_id": google_id},
                                                           {"last_login": datetime.now(dt.UTC)},
                                                           ttl=3600)

            response = {"user_details": user_data}
            if access_token != oauth.access_token:
                response["access_token"] = access_token
            return response

        @self.post("/logout")
        def logout(request: Request, oauth: OAuth):
            self._endpoint_logger.info(f"[LOGOUT:{request.client.host}] Received request to logout")
            access_token = oauth.access_token
            result = self._google_provider_manager.handle_logout(access_token)
            self._cache_db_handler.remove_from_cache(access_token)

            return result if result else {"message": "User logged out"}
