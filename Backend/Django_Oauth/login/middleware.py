from django.conf import settings
from django.http import JsonResponse
from django.contrib.auth import get_user_model
import jwt

class JWTAuthenticationMiddleware:

    def __init__(self, get_response): # get_response = next_middleware/route
        self.get_response = get_response
    
    def __call__(self, request):
        # Allow unauthenticated access to login and callback URLs
        if request.path in ["/auth/login/", "/auth/callback/"]:
            return self.get_response(request)
        
        # Extract the JWT token from Auth header or query parameters
        token = self.extract_token(request)

        if token is None:
            # Token isn't provided
            return JsonResponse({"error": "Token is required"}, status = 401)
        else:
            # Decode the token
            user = self.authenticate_user(token)
            if user is None:
                # respond with an error if token is invalif or user doesn't exist
                return JsonResponse({"error": "Unauthorized"}, status = 401)
            
            # Attach the user to the request object
            request.userobj = user

            # call next middleware or function
            return self.get_response(request)
        
        
    def extract_token(self, request):
        """
        Extracts the JWT token from the request cookies.

        Args:
            request: The incoming request object.

        Returns:
            str or None: The JWT token if found, otherwise None.
        """
        # Retrieve the token from cookies
        token = request.COOKIES.get('access_token')

        if token:
            return token 
        else: 
            return None


    def authenticate_user(self, token):
        """
        Authenticates the user based on the JWT token.

        Args:
            token: The JWT token string.

        Returns:
            User or None: The user object if authenticated, otherwise None.
        """
        try:
            # Decode the JWT using the secret key
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms = ["HS256"])
            username = payload.get("username")

            # Retrieve the user from the database
            User = get_user_model()
            # print("User object:", User.objects.get(username = username))                # Will call __str__ and print username
            return User.objects.get(username = username) # returns username because of __str__
            
        
        except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
            raise Exception("Invalid token")

        except User.DoesNotExist:
            raise Exception("User not found")
