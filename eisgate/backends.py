import logging, requests, base64

from django.contrib.auth import get_user_model
import django.conf
from django.core.exceptions import ObjectDoesNotExist

from eisgate.config import _EISConfig

logger = logging.getLogger(__name__)


class EisgateBackend(object):
    """
    This class implements the django authentication backend API
    """
    _settings = None
    _eis = None

    settings_prefix = 'AUTH_EIS_'
    default_settings = {}

    def __getstate__(self):
        """
        Exclude certain cached properties from pickling.
        """
        return dict((k, v) for (k, v) in self.__dict__.items()
                    if k not in ['_settings', '_eis'])

    def _get_settings(self):
        if self._settings is None:
            self._settings = EISSettings(self.settings_prefix,
                                         self.default_settings)

        return self._settings

    def _set_settings(self, settings):
        self._settings = settings

    settings = property(_get_settings, _set_settings)

    def _get_eis(self):
        if self._eis is None:
            options = getattr(django.conf.settings, 'AUTH_EIS_OPTIONS', None)

            self._eis = _EISConfig.get_eis(options)

        return self._eis
    eis = property(_get_eis)

    def get_user_model(self):
        return get_user_model()

    def authenticate(self, provider=None, token=None):
        if len(token) == 0:
            return None

        eis_user = _EISUser(self)
        user = eis_user.authenticate(provider, token)

        return user

    def get_user(self, user_id):
        user = None

        try:
            user = self.get_user_model().objects.get(pk=user_id)
            _EISUser(self, user=user)
        except ObjectDoesNotExist:
            pass

        return user

    def has_perm(self, user, perm, obj=None):
        return perm in self.get_all_permissions(user, obj)

    def has_module_perms(self, user, app_label):
        pass

    def get_all_permissions(self, user, obj=None):
        if hasattr(user, 'eis_user'):
            return user.eis_user.get_all_permissions()
        else:
            return set()

    def get_group_permissions(self, user, obj=None):
        pass

    def get_or_create_user(self, username, eis_user):
        model = self.get_user_model()
        username_field = getattr(model, 'USERNAME_FIELD', 'username')

        kwargs = {
            username_field + '__iexact': username,
            'defaults': {username_field: username.lower()}
        }

        return model.objects.get_or_create(**kwargs)


class _EISUser(object):
    """
    Represents an EIS user
    """
    class AuthenticationFailed(Exception):
        pass

    _user = None
    _groups = None
    _access_token = None
    _roles = None

    def __init__(self, backend, user=None):
        self.backend = backend

        if user is not None:
            self._set_authenticated_user(user)

    def __deepcopy__(self, memo):
        pass

    def __getstate__(self):
        return dict((k, v) for (k, v) in self.__dict__.items()
                    if k in ['backend', '_user'])

    def _set_authenticated_user(self, user):
        self._user = user

        user.eis_user = self

    def _get_eis(self):
        return self.backend.eis
    eis = property(_get_eis)

    def _get_settings(self):
        return self.backend.settings
    settings = property(_get_settings)


    def authenticate(self, provider, token):
        """
        Authenticates against EIS
        """
        user = None

        try:
            self._authenticate_user_eis()
            self._get_or_create_user(provider, token)

            user = self._user
        except self.AuthenticationFailed as e:
            logger.debug(u"Authentication failed for %s: %s" % ("username", e))

        return user

    def get_all_permissions(self):
        permissions = set(["eis.%s" % name for name in self._roles])
        return permissions

    def _authenticate_user_eis(self):
        self._get_access_token()

    def _get_or_create_user(self, provider, token, force_populate=False):
        """
        Loads the user from DB or creates a new instance if it does not exist
        """
        save_user = False

        if not self._access_token:
            return None
        headers = {'Authorization': 'Bearer ' + self._access_token}
        payload = {'token': token}
        validation_url = self.settings.SERVER_URL + '/auth/validate/'
        response = requests.post(validation_url, headers=headers, data=payload, verify=False)
        if response.status_code != requests.codes.ok:
            return None
        data = response.json()

        if not data['active']:
            return None

        #We got a response with a uuid
        eis_uuid = data['sub']
        user_uuid = eis_uuid.replace('-', '')

        #We need to assign permissions = roles to a user
        self._roles = data['roles']

        self._user, created = self.backend.get_or_create_user(user_uuid[0:30], self)
        self._user.eis_user = self

        populate = force_populate or self.settings.ALWAYS_UPDATE_USER or created

        if created:
            logger.debug("Created Django user %s", user_uuid[0:30])
            self._user.set_unusable_password()
            save_user = True

        if populate:
            logger.debug("Populating Django user %s", user_uuid[0:30])
            self._populate_user()
            save_user = True

        if save_user:
            self._user.save()

    def _populate_user(self):
        pass

    def _get_access_token(self):
        encoded_client_credentials = base64.b64encode(self.settings.CLIENT_ID + ':' + self.settings.CLIENT_SECRET)
        backend_headers = {'Authorization': 'Basic ' + encoded_client_credentials}
        backend_payload = {'grant_type': 'client_credentials_b', 'scope': 'read+write'}
        backend_token_url = self.settings.SERVER_URL + '/oauth2/access_token/'

        try:
            token_response = requests.post(backend_token_url, headers=backend_headers, data=backend_payload, verify=False, timeout=3.0)
            if token_response.status_code == requests.codes.ok:
                token_data = token_response.json()
                if token_data is not None and token_data['access_token'] is not None:
                    self._access_token = token_data['access_token']
        except requests.exceptions.RequestException as ex:
            logger.error(ex)



class EISSettings(object):
    """
    Settings for EisGate
    """
    defaults = {
        'ALWAYS_UPDATE_USER': False,
        'CLIENT_ID': None,
        'CLIENT_SECRET': None,
        'SERVER_URL': 'http://localhost',
    }

    def __init__(self, prefix='AUTH_EIS_', defaults={}):
        defaults = dict(self.defaults, **defaults)

        for name, default in defaults.items():
            value = getattr(django.conf.settings, prefix + name, default)
            setattr(self, name, value)