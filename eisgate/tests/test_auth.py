from django.contrib.auth import get_user_model
from django.contrib.auth.models import User
from django.db import models
from django.test.client import RequestFactory
import pytest, requests, json

pytestmark = pytest.mark.django_db

class BaseUser(models.Model):
    class Meta:
        db_table = u'base_user'
        app_label = 'eisgate'

    user = models.OneToOneField(User, null=True)
    user_uuid = models.CharField(max_length=255, editable=False)


def test_backend_authenticate_create_new_user(settings):
    from eisgate.backends import EisgateBackend

    backend = EisgateBackend()
    auth_user = backend.authenticate(token='a159e3e32a4a51129369b650efddc115aa5dfea7')

    assert auth_user is not None


def test_backend_middleware(settings):
    from eisgate.middleware import EisgateMiddleware

    middleware = EisgateMiddleware()

    #create request
    rf = RequestFactory()
    req = rf.get('/hello', HTTP_AUTHORIZATION='Bearer a159e3e32a4a51129369b650efddc115aa5dfea7')

    middleware.process_request(request=req)

    assert req.user.is_authenticated() == True


def test_valid_token(settings):
    from eisgate.backends import OAuth2Token

    json_response = {'access_token': '12f5', 'expires_in': 31535999, 'scope': 'read'}
    token = OAuth2Token.from_json(json_response)

    assert token.valid is True


def test_invalid_token(settings):
    from eisgate.backends import OAuth2Token

    json_response = {'access_token': '12f5', 'expires_in': -5, 'scope': 'read'}
    token = OAuth2Token.from_json(json_response)

    assert token.valid is False


def test_provider_uses_same_token(settings):
    from eisgate.backends import Oauth2TokenProvider

    identity_url = getattr(settings, 'IDENTITY_URL', 'http://accounts.lcl.ezeep.com')
    backend_token_url = identity_url + '/oauth2/access_token/'
    provider = Oauth2TokenProvider(url=backend_token_url)

    eis_token = provider.fetch_token()
    assert eis_token is not None

    eis_token2 = provider.fetch_token()
    assert eis_token == eis_token2

    eis_token3 = provider.fetch_token(force_new=True)
    assert eis_token != eis_token3
    assert eis_token3 is not None



