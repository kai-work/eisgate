import logging, requests, base64
from datetime import datetime, timedelta

from django.conf import settings
from django.contrib.auth import get_user_model


logger = logging.getLogger(__name__)


class OAuth2Token(object):
    def __init__(self, value, expires_in, scope, token_type='Bearer'):
        exp_date = expires_in
        if not isinstance(expires_in, datetime):
            exp_date = datetime.utcnow() + timedelta(seconds=expires_in)

        self.value = value
        self.expires_in = exp_date
        self.scope = scope
        self.token_type = token_type

    @classmethod
    def from_json(cls, json_data):
        return cls(json_data['access_token'], json_data['expires_in'], json_data['scope'])

    @property
    def valid(self):
        if datetime.utcnow() <= self.expires_in:
            return True
        return False


class Oauth2TokenProvider(object):
    def __init__(self, url='https://accounts.ezeep.com/oauth/access_token/'):
        self._token = None
        self.url = url

    def fetch_token(self, force_new=False):
        if force_new or not self._token or not self._token.valid:
            backend_client_id = getattr(settings, 'EIS_CLIENT_ID', '')
            backend_client_secret = getattr(settings, 'EIS_CLIENT_SECRET', '')
            encoded_client_credentials = base64.b64encode(backend_client_id + ':' + backend_client_secret)
            backend_headers = {'Authorization': 'Basic ' + encoded_client_credentials}
            backend_payload = {'grant_type': 'client_credentials', 'scope': 'internal:read'}

            try:
                token_response = requests.post(self.url, headers=backend_headers, data=backend_payload,
                                               verify=False, timeout=3.0)
                if token_response.status_code == requests.codes.ok:
                    token_data = token_response.json()
                    self._token = OAuth2Token.from_json(token_data)
            except requests.exceptions.RequestException as ex:
                logger.error(ex)
        return self._token


identity_url = getattr(settings, 'IDENTITY_URL', 'https://accounts.ezeep.com')
backend_token_url = identity_url + '/oauth2/access_token/'
token_provider = Oauth2TokenProvider(url=backend_token_url)


class EisgateBackend(object):
    def __init__(self):
        self.token_provider = token_provider

    def authenticate(self, provider=None, token=None):
        # We need to verify the token against EIS and get a identifier
        UserModel = get_user_model()
        identity_url = getattr(settings, 'IDENTITY_URL', 'https://accounts.ezeep.com')

        validation_url = identity_url + '/auth/validate/'

        eis_token = self.token_provider.fetch_token()
        headers = {'Authorization': 'Bearer ' + eis_token.value}
        payload = {'token': token}

        user_data = self.validate(validation_url, headers, payload)
        if not user_data or not user_data['active']:
            return None

        eis_uuid = user_data['sub']
        user_uuid = eis_uuid.replace('-', '')
        try:
            user = UserModel.objects.get(username=user_uuid[0:30])
        except UserModel.DoesNotExist:
            user = UserModel(username=user_uuid[0:30])
            user.set_unusable_password()
            user.save() #TODO, we might need user.user.save() with backend
        return user

    def validate(self, url, headers, payload, max_attempts=2):
        attempt = 1
        while max_attempts >= attempt:
            try:
                response = requests.post(url, headers=headers, data=payload, verify=False)
            except requests.RequestException as ex:
                if attempt == max_attempts:
                    logger.error(ex)
                else:
                    self.token_provider.fetch_token(force_new=True)
            if response.status_code != requests.codes.ok:
                if attempt == max_attempts:
                    logger.error('Error validation token')
                else:
                    self.token_provider.fetch_token(force_new=True)
            else:
                data = response.json() if response else None
                return data
            attempt += 1
        return None

    def get_user(self, user_id):
            return None
