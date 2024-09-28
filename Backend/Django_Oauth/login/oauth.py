from requests.auth import HTTPBasicAuth # Import for basic HTTP authentication
from urllib.parse import urlencode
import requests # Import requests for HTTP requests

# Step 1: Define the AuthorizationServer class to handle GitLab OAuth logic
class AuthorizationServer:

    def __init__(self, url, client_id, client_secret):
        self.url = url  # GitLab OAuth base url
        self.client_id = client_id  # GitLab Client ID for identifying the application
        self.client_secret = client_secret # Gitlab Client Secret for application authentication


    def authorize(self, redirect_uri, state, scope="read_user openid profile email"):
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
    
