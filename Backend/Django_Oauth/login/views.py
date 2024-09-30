import os
import secrets
import jwt
from dotenv import load_dotenv
from datetime import datetime, timedelta
from django.conf import settings

from django.shortcuts import redirect, render
from django.http import HttpResponse, HttpResponseBadRequest, HttpResponseRedirect, JsonResponse
from django.urls import reverse
from django.contrib.auth import get_user_model
import requests

from login.oauth import AuthorizationServer

# Now you can retrieve your environment variables
GITLAB_SERVER = os.getenv("GITLAB_SERVER", "https://gitlab.com/")  # Default is https://gitlab.com/
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
        redirect_uri=request.build_absolute_uri(reverse('callback')), # full callback URL
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
        redirect_uri = request.build_absolute_uri(reverse('callback')), # same callback URL as a security check and not for redirecting!
        code = code
    )

    # Step 9: Use the access token to get user information from GitLab
    access_token = token_response.get("access_token")

    # Make a GET request to the GitLab API to retrieve user info
    user_info = requests.get(
        f"{GITLAB_SERVER}api/v4/user",
        headers={"Authorization": f"Bearer {access_token}"}  # Use Bearer token in the Authorization header
    )

    user_info.raise_for_status() # Raise an error for any bad response
    user_data = user_info.json() # Get user information as a JSON dictionary

    # Step 10: Create or get the user in the Django database
    User = get_user_model() # django user model
    user, created = User.objects.get_or_create(
        username = user_data["username"],
        defaults = {"email": user_data["email"]} # set the email if creating a new user
    )

    # Step 11: Generate JWT access and refresh tokens
    access_token, refresh_token = generate_jwt_tokens(user)

    # Create a redirect response
    response = HttpResponseRedirect("http://localhost:4200/")

    # Step 12: Set tokens as HTTP-only cookies
    response.set_cookie('access_token', access_token, httponly=True, secure=False)
    response.set_cookie('refresh_token', refresh_token, httponly=True, secure=False)
    response.set_cookie('username', user.username)

    # Return the redirect response
    return response

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
        'username': user.username,
        'exp': datetime.utcnow() + timedelta(minutes=15),
        'iat': datetime.utcnow() # indicates when the token was created
    }, settings.SECRET_KEY, algorithm='HS256')

    # Refresh token - long lived
    refresh_token = jwt.encode({
        'username': user.username,
        'exp': datetime.utcnow() + timedelta(days=7),
        'iat': datetime.utcnow() # indicates when the token was created
    }, settings.SECRET_KEY, algorithm='HS256')

    return access_token, refresh_token


# Endpoint to check if the user is authenticated
def check_authentication(request):
    if request.username:
        return JsonResponse({"authenticated": True, "user": request.username})
    else:
        return JsonResponse({"authenticated": False}, status=401)