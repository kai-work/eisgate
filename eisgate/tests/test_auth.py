from django.contrib.auth import get_user_model
from django.contrib.auth.models import User
from django.db import models
from django.test.client import RequestFactory
import pytest, requests

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
    auth_user = backend.authenticate(token='d3279e66c05bec66635254a832efe8da3688b153')

    assert auth_user is not None


def test_backend_middleware(settings):
    from eisgate.middleware import EisgateMiddleware

    middleware = EisgateMiddleware()

    #create request
    rf = RequestFactory()
    req = rf.get('/hello', HTTP_AUTHORIZATION='Bearer d3279e66c05bec66635254a832efe8da3688b153')

    middleware.process_request(request=req)

    assert req.user.is_authenticated() == True

