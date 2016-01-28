from django.contrib.auth import authenticate

class EisgateMiddleware(object):
    """
    Middleware for EIS user authentication
    """
    def process_request(self, request):
        # do something only if request contains a Bearer token
        if request.META.get('HTTP_AUTHORIZATION', '').startswith('Bearer'):
            if not hasattr(request, 'user') or request.user.is_anonymous():
                #user = authenticate(request=request)
                token = request.META.get('HTTP_AUTHORIZATION').split(' ')
                user = authenticate(token=token[1])
                if user:
                    request.user = request._cached_user = user
