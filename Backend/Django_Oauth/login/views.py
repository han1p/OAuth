import os
import requests # Import requests for HTTP requests
import secrets
import jwt
from datetime import datetime, timedelta
from requests.auth import HTTPBasicAuth # Import for basic HTTP authentication
from urllib.parse import urlencode
from django.conf import settings

from django.shortcuts import redirect, render
from django.http import HttpResponse, HttpResponseBadRequest, JsonResponse
from django.urls import reverse
from django.contrib.auth import get_user_model

# Create your views here.
def home(request):
    return HttpResponse("Hello, Django!")

# Step 1: Define the AuthorizationServer class to handle GitLab OAuth logic
class AuthorizationServer:

    def __init__(self, url, client_id, client_secret):
        self.url = url  # GitLab OAuth base url
        self.client_id = client_id  # GitLab Client ID for identifying the application
        self.client_secret = client_secret # Gitlab Client Secret for application authentication


    def authorize(self, redirect_uri, state, scope="read_user"):
        """
        Generate the authorization url to redirect the user to GitLab.

        Args:
            redirect_uri(str): The URI to redirect after the authorization
            state(str): An arbitary string to maintain state between the request and callback
            scope(str): The level of access requested(default is "read_user")

        Returns:
            str: The full authorization URL
        """

        return self.url + "oauth/authorize?" + urlencode({
            "client_id": self.client_id,
            "response_type": "code", # The response type, indicating that we expect an authorization code
            "redirect_uri": redirect_uri, # The callback url that GitLab will direct to
            "state": state, # Unique string to prevent CSRF attacks
            "scope": scope, # The scope of access requested
        })

    
    def request_token(self, redirect_uri, code):
        """
        Exchange the authorization code for an access token.

        Args:
            redirect_uri(str): The URI to redirect to after requesting the token
            code(str): The authorization code received from GitLab

        Returns:
            dict: The JSON response containing the access token and other data
        """
        
        # client_auth - needs to be passed has an authentication header to verify the identity of the application to GitLab
        client_auth = HTTPBasicAuth(self.client_id, self.client_secret)

        # make a post request to GitLab's token endpoint
        response = requests.post(self.url + "oauth/token", auth=client_auth, data={
            "grant_type": "authorization_code", # indicates the type of request being made
            "redirect_uri": redirect_uri, # same redirect uri used in authorization request
            "code": code, # The authorization code received from GitLab
        }) 

        response.raise_for_status() # Raise an error for any bad responses
        return response.json()   # returns the response as a JSON dictionary
    

# Step 4: Load the environment variables for GitLab credentials
GITLAB_SERVER = os.getenv("GITLAB_SERVER", "https://gitlab.com/")
GITLAB_CLIENT_ID = os.getenv("GITLAB_CLIENT_ID")
GITLAB_CLIENT_SECRET = os.getenv("GITLAB_CLIENT_SECRET")

# Step 5: Initialize the AuthorizationServer instance with GitLab credentials
gitlab_oauth = AuthorizationServer(GITLAB_SERVER, GITLAB_CLIENT_ID, GITLAB_CLIENT_SECRET)

# Step 6: View to initiate login with GitLab
def login(request):
    """
    Redirect the user to the GitLab authorization url

    Args:
        request: The HTTP request object containing metadata about the request

    Returns:
        HttpResponse: A redirect to the GitLab authorization url
    """

    # Step 6.1: Generate a unique state value for CSRF protection and store it in the session
    state = secrets.token_urlsafe(16) # generates a random URL-safe state value
    request.session['oauth_state'] = state # store the state value in the session

    return redirect(gitlab_oauth.authorize(
        redirect_uri=request.build.absolute_uri(reverse('callback')), # full callback URL
        state = state # include state value to maintain security
    ))

# Step 7: View to handle the callback from GitLab after user authorization
def callback(request):
    """
    Handle the callback from GitLab after the user has authorized.

    Args:
        request: The HTTP request object containing the authorization code and state

    Returns:
        HttpResponse: A redirect to the frontend after successful login
    """

    # Step 7.1: Retrieve the state value from the callback request
    returned_state = request.GET.get('state')
    original_state = request.session.pop('oauth_state', None) # Get and remove the state from the session

    # Step 7.2: Validate the state to protect against CSRF attacks
    if returned_state != original_state:
        return HttpResponseBadRequest("Invalid state parameter") # state mistmatch, reject the request
    
    # Step 7.3: Retrieve the authorization code from the callback request parameters
    code = request.GET.get('code') 

    # Step 8: Request the access token using the authorization code
    token_response = gitlab_oauth.request_token(
        redirect_uri = request.build_absolute_uri(reverse('callback')), # same callback URL
        code = code
    )

    # Step 9: Use the access token to get user information from GitLab
    user_info = request.get(f"{GITLAB_SERVER}api/v4/user", params = {
        "access_token": token_response["access_token"] # pass the access token as a query parameter
    })
    user_info.raise_for_status() # Raise an error for any bad response
    user_data = user_info.json() # Get user information as a JSON dictionary

    # Step 10: Create or get the user in the Django database
    User = get_user_model() # django user model
    user, created = User.objects.get_or_create(
        username = user_data["username"],
        defaults = {"email": user_data["email"]} # set the email if creating a new user
    )

    # Step 11: Generate JWT access and refresh tokens
    access_token, refersh_token = generate_jwt_tokens(user)

    # Step 12: Send the tokens back to the frontend as JSON
    return JsonResponse({
        'access_token': access_token,
        'refresh_token': refersh_token,
        'email': user.email
    })

# Generate jwt token
def generate_jwt_tokens(user):
    """
    Generate both access and refresh tokens for the user.

    Args:
        user: user object

    Returns:
        access_token, refresh_token: jwt access and refresh token 
    """

    # Access token - short lived
    access_token = jwt.encode({
        'email': user.email,
        'exp': datetime.utcnow() + timedelta(minutes=15),
        'iat': datetime.utcnow() # indicates when the token was created
    }, settings.SECRET_KEY, algorithm='HS256')

    # Refresh token - long lived
    refresh_token = jwt.encode({
        'email': user.email,
        'exp': datetime.utcnow() + timedelta(days=7),
        'iat': datetime.utcnow() # indicates when the token was created
    }, settings.SECRET_KEY, algorithm='HS256')

    return access_token, refresh_token


# Decode jwt token
def decode_jwt_token(token):
    """
    Decode the JWT token.

    Args:
        token: The JWT token string to decode

    Returns:
        dict: The decoded JWT payload
    """

    try:
        # Decode the JWT using the same secret key and algorithm
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['H256'])
        return payload
    except jwt.ExpiredSignatureError:
        return {"error": "Token has expired"}
    except jwt.InvalidTokenError:
        return {"error": "Invalid token"}
    
def decode_view(request):
    """
    View to decode JWT token from the request.

    Args:
        request: The HTTP request object containing the token

    Returns:
        JsonResponse: Decoded JWT payload or error
    """

    # check if the token is passed in the Authorization header
    auth_header = request.headers.get("Authorization")
    token = None

    if auth_header and auth_header.startswith("Bearer "):
        # extract the token after the bearer
        token = auth_header.split(" ")[1]

    # fallback - get the token from query params, if not passed in the header
    if not token:
        token = request.GET.get("token")

    if not token:
        return JsonResponse({"error": "Token is required"}, status = 400)

    decoded_payload = decode_jwt_token(token)

    # extract the user email from the payload
    user_email = decoded_payload.get("email")

    # look up for the user in the database
    User = get_user_model()
    
    try:
        user = User.objects.get(email=user_email)
    except User.DoesNotExist:
        return {"error": "User not found"}
    
    # return user info or token payload for further authorization(allowing post request only to white listed users)
    return {
        "email": user.email,
        "username": user.username,
    }