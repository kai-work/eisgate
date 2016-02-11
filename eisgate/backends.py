import logging, requests, base64

from django.conf import settings
from django.contrib.auth import get_user_model


logger = logging.getLogger(__name__)


class EisgateBackend(object):
    """

    """
    def authenticate(self, provider=None, token=None):
        # We need to verify the token against EIS and get a identifier
        UserModel = get_user_model()
        uuid_attr = getattr(settings, 'UUID_ATTR', 'pk')
        identity_url = getattr(settings, 'IDENTITY_URL', 'https://accounts.ezeep.com')

        validation_url = identity_url + '/auth/validate/'
        access_token_eis = get_access_token_for_eis()
        if not access_token_eis:
            return None
        headers = {'Authorization': 'Bearer ' +access_token_eis}
        payload = {'token': token}
        response = requests.post(validation_url, headers=headers, data=payload, verify=False)
        if response.status_code != requests.codes.ok:
            return None
        data = response.json()

        if not data['active']:
            return None

        #We got a response with a uuid
        eis_uuid = data['sub']
        user_uuid = eis_uuid.replace('-', '')
        try:
            user = UserModel.objects.get(username=user_uuid[0:30])
        except UserModel.DoesNotExist:
            user = UserModel(username=user_uuid[0:30])
            user.set_unusable_password()
            user.save() #TODO, we might need user.user.save() with backend
        return user

    def get_user(self, user_id):
            return None

def get_access_token_for_eis():
    # We need an auth token from EIS, but lets cache the token #TOD
    identity_url = getattr(settings, 'IDENTITY_URL', 'https://accounts.ezeep.com')
    backend_client_id = getattr(settings, 'EIS_CLIENT_ID', '')
    backend_client_secret = getattr(settings, 'EIS_CLIENT_SECRET', '')
    encoded_client_credentials = base64.b64encode(backend_client_id + ':' + backend_client_secret)
    backend_token_url = identity_url + '/oauth2/access_token/'
    backend_headers = {'Authorization': 'Basic ' + encoded_client_credentials}
    backend_payload = {'grant_type': 'client_credentials_b', 'scope': 'read+write'}
    try:
        token_response = requests.post(backend_token_url, headers=backend_headers, data=backend_payload, verify=False, timeout=3.0)
        if token_response.status_code == requests.codes.ok:
            token_data = token_response.json()
            if token_data is not None and token_data['access_token'] is not None:
                return token_data['access_token']
    except requests.exceptions.RequestException as ex:
        logger.error(ex)
        return None
    return None