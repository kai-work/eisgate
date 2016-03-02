from django.conf import settings

def pytest_configure():
    settings.configure(
            AUTH_EIS_CLIENT_ID = 'test',
            AUTH_EIS_CLIENT_SECRET = '1234',
            AUTH_EIS_SERVER_URL = 'http://10.0.2.2:8081',
            EIS_CLIENT_ID = 'test',
            EIS_CLIENT_SECRET = '1234',
            IDENTITY_URL = 'http://10.0.2.2:8081',
            IDENTITY_SERVICE = 'tcp://10.8.0.74:4242',
            IDENTITY_BACKEND = 'http://accounts.ezeep.com/auth/signin/?next=%s',

            BASE_URL = 'http://service1.ezeep.com',
            DEBUG = True,

            DATABASES = {
                'default': {
                    'ENGINE': 'django.db.backends.sqlite3',
                    'NAME': ':memory',
                    'TEST_NAME': ':memory',
                }
            },

            SECRET_KEY = 'abcdefghi',

            # ROOT_URLCONF = 'myapp.urls'
            INSTALLED_APPS = (
                'django.contrib.auth',
                'django.contrib.contenttypes',
                'django.contrib.sessions',
                'django.contrib.admin',),

            MIDDLEWARE_CLASSES = (
                'eisgate.middleware.EisgateMiddleware',
            ),

            AUTHENTICATION_BACKENDS = (
                'eisgate.backends.EisgateBackend',
            ),

            UUID_ATTR = 'username',
    )