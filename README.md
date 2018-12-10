# firebase_fave
Firebase Admin Verify Everyone!  For Python.

Some duct tape for firebase_admin to add verification and facilitate credentialing.

# installation
`pip install firebase_fave`

# usage
```python
import firebase_admin
import firebase_fave
import time

RELEASE_TIME = 1544470743

# verify user:
firebase_admin.verify_user('the_password', email='the_email') # can also use uid

# require credentials (as well as a valid idToken)
# NOTE: requires a firestore collection named "user_claims", documents keyed by uid and containing the claims
@require_creds({'access_flag': lambda x: x & 8, 'release_lag', lambda x: time.time() > RELEASE_TIME + x})
def get(self, ...
```
