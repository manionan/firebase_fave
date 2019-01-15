import time
from functools import wraps
from flask import abort, request

# import several different ways to make the code read like it would as part of the package it belongs in
import firebase_admin
from firebase_admin._user_mgt import *
from firebase_admin.auth import _get_auth_service, AuthError
from firebase_admin import firestore


# helper to add methods
def _add_method(cls):
    def cls_decorator(func):
        @wraps(func)
        def copied(self, *args, **kwargs): # wrap so we don't bind the func
            return func(self, *args, **kwargs)
        setattr(cls, func.__name__, copied)
        return func
    return cls_decorator


# add password verify to user manager
@_add_method(firebase_admin._user_mgt.UserManager)
def verify_user(self, **kwargs):
    """Gets the user data corresponding to the provided data and verifies"""
    key, key_type = self.get_user(**kwargs)['email'], 'email'

    if 'password' in kwargs:
        password = kwargs.pop('password')
    else:
        password = ''

    payload = {key_type:key, 'password':password, "returnSecureToken": True}

    try:
        response = self._client.request('post', 'verifyPassword', json=payload)
    except requests.exceptions.RequestException as error:
        msg = 'Failed to get user by {0}: {1}.'.format(key_type, key)
        self._handle_http_error(INTERNAL_ERROR, msg, error)
    else:
        if not response:
            raise ApiCallError(
                USER_NOT_FOUND_ERROR,
                'No user record found for the provided {0}: {1}.'.format(key_type, key))
        return response


# as in firebase_admin, we want a convenience method as well
def _outer_verify_user(password, **kwargs):
    """Verifies a user given password and one of uid or email.
    Args:
        uid: A user ID string.
        email: user e-mail address.
        app: An App instance (optional).
    
    Returns:
        UserRecord: A UserRecord instance.
        
    Raises:
        ValueError: if both user ID and email are None, empty, or malformed
        AuthError: If an error occurs while deleting the user account.
    """
    app = kwargs.pop('app', None)
    user_manager = _get_auth_service(app).user_manager
    kwargs['password'] = password
    try:
        return user_manager.verify_user(**kwargs)
    except firebase_admin._user_mgt.ApiCallError as error:
        raise AuthError(error.code, str(error), error.detail)


# finally, apply this convenience method to the class.
firebase_admin.verify_user = _outer_verify_user


# wrapper function to require credentials and claims!
def require_creds(creds_reqs={}):

    def real_require_creds(protected_function):

        @wraps(protected_function)
        def protector(*args, **kwargs):
            token = request.args.get('idToken', '')
            try:
                auth_resp = firebase_admin.auth.verify_id_token(token, check_revoked=True)
                claims = firebase_admin.firestore.client().collection('user_claims')\
                    .document(auth_resp['user_id']).get().to_dict()
            except:
                abort(401)

            if 'exp' in auth_resp\
                    and auth_resp['exp'] > time.time()\
                    and min(*[bool(creds_reqs[k](v)) for k, v in claims.items() if k in creds_reqs.keys()]):
                return protected_function(*args, **kwargs)
            else:
                abort(401)

        return protector

    return real_require_creds
