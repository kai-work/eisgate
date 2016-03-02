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


@pytest.fixture()
def eisgate_mocked(monkeypatch):
    from eisgate.backends import EisgateBackend, _EISUser
    backend = EisgateBackend()

    def mockEisToken(self):
       self._access_token = "abcd"
    monkeypatch.setattr(_EISUser, '_get_access_token', mockEisToken)

    def mockRequest(validation_url, headers=None, data=None, verify=False):
        class Response:
            status_code = requests.codes.ok
            def json(self):
                return json.loads('{"username": "bob", ' \
                                  '"sub": "bac76266-090d-4744-b6d8-a3d137e3571f", ' \
                                  '"client_id": "3bc69020b4d9d47aab50", ' \
                                  '"exp": 1453555840, ' \
                                  '"active": true, ' \
                                  '"scope": "read+write" , ' \
                                  '"roles": ["r_user", "r_user_manager"]}')

        return Response()
    monkeypatch.setattr(requests, 'post', mockRequest)

    return backend


def test_backend_authenticate_create_new_user(settings, eisgate_mocked):
    backend = eisgate_mocked
    auth_user = backend.authenticate(token='abcd')

    assert auth_user is not None


def test_existing_user(monkeypatch, eisgate_mocked, settings):
    backend = eisgate_mocked

    User.objects.create(username='bac76266090d4744b6d8a3d137e3571f'[0:30])
    user_count = User.objects.count()

    user = backend.authenticate(token='abcd')

    assert user is not None
    assert user_count == User.objects.count()


def test_get_group_permissions(settings, eisgate_mocked):
    backend = eisgate_mocked
    auth_user = backend.authenticate(token='abcd')
    permissions = backend.get_all_permissions(auth_user)
    assert len(permissions) > 0

    assert backend.has_perm(auth_user, "eis.r_user") is True
    assert backend.has_perm(auth_user, "eis.r_user_manager") is True
    assert backend.has_perm(auth_user, "eis.r_printer_provider") is False


def test_get_user(settings, eisgate_mocked):
    backend = eisgate_mocked

    auth_user = backend.authenticate(token='abcd')
    get_user = backend.get_user(auth_user.id)

    assert get_user is not None
    assert get_user == auth_user


def test_middleware(settings, eisgate_mocked):
    from eisgate.middleware import EisgateMiddleware
    middleware = EisgateMiddleware()

    rf = RequestFactory()
    req = rf.get('/hello', HTTP_AUTHORIZATION='Bearer abcd')

    middleware.process_request(request=req)

    assert req.user.is_authenticated() == True