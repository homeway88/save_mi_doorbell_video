import logging
import json
import time
import string
import random
import base64
import hashlib
import micloud
import requests
from urllib import parse

from micloud import miutils
from micloud.micloudexception import MiCloudException

try:
    from micloud.micloudexception import MiCloudAccessDenied
except (ModuleNotFoundError, ImportError):
    class MiCloudAccessDenied(MiCloudException):
        """ micloud==0.4 """

_LOGGER = logging.getLogger(__name__)
ACCOUNT_BASE = 'https://account.xiaomi.com'
UA = "Android-7.1.1-1.0.0-ONEPLUS A3010-136-%s APP/xiaomi.smarthome APPV/62830"


class RC4:
    _idx = 0
    _jdx = 0
    _ksa: list

    def __init__(self, pwd):
        self.init_key(pwd)

    def init_key(self, pwd):
        cnt = len(pwd)
        ksa = list(range(256))
        j = 0
        for i in range(256):
            j = (j + ksa[i] + pwd[i % cnt]) & 255
            ksa[i], ksa[j] = ksa[j], ksa[i]
        self._ksa = ksa
        self._idx = 0
        self._jdx = 0
        return self

    def crypt(self, data):
        if isinstance(data, str):
            data = data.encode()
        ksa = self._ksa
        i = self._idx
        j = self._jdx
        out = []
        for byt in data:
            i = (i + 1) & 255
            j = (j + ksa[i]) & 255
            ksa[i], ksa[j] = ksa[j], ksa[i]
            out.append(byt ^ ksa[(ksa[i] + ksa[j]) & 255])
        self._idx = i
        self._jdx = j
        self._ksa = ksa
        return bytearray(out)

    def init1024(self):
        self.crypt(bytes(1024))
        return self


class MiotCloud(micloud.MiCloud):
    def __init__(self, username, password, country=None, sid=None):
        try:
            super().__init__(username, password)
        except (FileNotFoundError, KeyError):
            self.timezone = 'GMT+00:00'
        self.username = username
        self.password = password
        self.default_server = country or 'cn'
        self.sid = sid or 'xiaomiio'
        self.agent_id = self.get_random_string(16)
        self.client_id = self.agent_id
        self.useragent = UA % self.client_id
        self.http_timeout = 10
        self.login_times = 0
        self.attrs = {}

    @property
    def unique_id(self):
        uid = self.user_id or self.username
        return f'{uid}-{self.default_server}-{self.sid}'

    def get_properties_for_mapping(self, did, mapping: dict):
        pms = []
        rmp = {}
        for k, v in mapping.items():
            if not isinstance(v, dict):
                continue
            s = v.get('siid')
            p = v.get('piid')
            pms.append({'did': str(did), 'siid': s, 'piid': p})
            rmp[f'prop.{s}.{p}'] = k
        rls = self.get_props(pms)
        if not rls:
            return None
        dls = []
        for v in rls:
            s = v.get('siid')
            p = v.get('piid')
            k = rmp.get(f'prop.{s}.{p}')
            if not k:
                continue
            v['did'] = k
            dls.append(v)
        return dls

    def get_props(self, params=None):
        return self.request_miot_spec('prop/get', params)

    def set_props(self, params=None):
        return self.request_miot_spec('prop/set', params)

    def do_action(self, params=None):
        return self.request_miot_spec('action', params)

    def request_miot_spec(self, api, params=None):
        rdt = self.request_miot_api('miotspec/' + api, {
            'params': params or [],
        }) or {}
        rls = rdt.get('result')
        if not rls and rdt.get('code'):
            raise MiCloudException(json.dumps(rdt))
        return rls

    def get_user_device_data(self, did, key, typ='prop', raw=False, **kwargs):
        now = int(time.time())
        timeout = kwargs.pop('timeout', self.http_timeout)
        params = {
            'did': did,
            'key': key,
            'type': typ,
            'time_start': now - 86400 * 7,
            'time_end': now + 60,
            'limit': 5,
            **kwargs,
        }
        rdt = self.request_miot_api('user/get_user_device_data', params, timeout=timeout) or {}
        return rdt if raw else rdt.get('result')

    def get_last_device_data(self, did, key, typ='prop', **kwargs):
        kwargs['raw'] = False
        kwargs['limit'] = 1
        rls = self.get_user_device_data(did, key, typ, **kwargs) or [None]
        rdt = rls.pop(0) or {}
        if kwargs.get('not_value'):
            return rdt
        val = rdt.get('value')
        if val is None:
            return None
        try:
            vls = json.loads(val)
        except (TypeError, ValueError):
            vls = [val]
        return vls.pop(0)

    def request_miot_api(self, api, data, method='POST', crypt=True, debug=True, **kwargs):
        params = {}
        if data is not None:
            params['data'] = self.json_encode(data)
        raw = kwargs.pop('raw', self.sid != 'xiaomiio')
        rsp = None
        try:
            if raw:
                rsp = self.request_raw(api, data, method, **kwargs)
            elif crypt:
                rsp = self.request_rc4_api(api, params, method, **kwargs)
            else:
                rsp = self.request(self.get_api_url(api), params, **kwargs)
            rdt = json.loads(rsp)
            if debug:
                _LOGGER.debug(
                    'Request miot api: %s %s result: %s',
                    api, data, rsp,
                )
            self.attrs['timeouts'] = 0
        except requests.exceptions.Timeout as exc:
            rdt = None
            self.attrs.setdefault('timeouts', 0)
            self.attrs['timeouts'] += 1
            if 5 < self.attrs['timeouts'] <= 10:
                _LOGGER.error('Request xiaomi api: %s %s timeout, exception: %s', api, data, exc)
        except (TypeError, ValueError):
            rdt = None
        code = rdt.get('code') if rdt else None
        if code == 3:
            self._logout()
            _LOGGER.warning('Unauthorized while executing request to %s, logged out.', api)
        elif code or not rdt:
            fun = _LOGGER.info if rdt else _LOGGER.warning
            fun('Request xiaomi api: %s %s failed, response: %s', api, data, rsp)
        return rdt

    def get_device_list(self):
        rdt = self.request_miot_api('home/device_list', {
            'getVirtualModel': True,
            'getHuamiDevices': 1,
            'get_split_device': False,
            'support_smart_home': True,
        }, debug=False, timeout=60) or {}
        if rdt and 'result' in rdt:
            return rdt['result']['list']
        _LOGGER.warning('Got xiaomi cloud devices for %s failed: %s', self.username, rdt)
        return None

    def get_home_devices(self):
        rdt = self.request_miot_api('homeroom/gethome', {
            'fetch_share_dev': True,
        }, debug=False, timeout=60) or {}
        rdt = rdt.get('result') or {}
        rdt.setdefault('devices', {})
        for h in rdt.get('homelist', []):
            for r in h.get('roomlist', []):
                for did in r.get('dids', []):
                    rdt['devices'][did] = {
                        'home_id': h.get('id'),
                        'room_id': r.get('id'),
                        'home_name': h.get('name'),
                        'room_name': r.get('name'),
                    }
        return rdt

    def _logout(self):
        self.service_token = None

    def _login_request(self, captcha=None):
        self._init_session()
        auth = self.attrs.pop('login_data', None)
        if captcha and auth:
            auth['captcha'] = captcha
        if not auth:
            auth = self._login_step1()
        location = self._login_step2(**auth)
        response = self._login_step3(location)
        http_code = response.status_code
        if http_code == 200:
            return True
        elif http_code == 403:
            raise MiCloudAccessDenied(f'Login to xiaomi error: {response.text} ({http_code})')
        else:
            _LOGGER.error(
                'Xiaomi login request returned status %s, reason: %s, content: %s',
                http_code, response.reason, response.text,
            )
            raise MiCloudException(f'Login to xiaomi error: {response.text} ({http_code})')

    def _login_step1(self):
        response = self.session.get(
            f'{ACCOUNT_BASE}/pass/serviceLogin',
            params={'sid': self.sid, '_json': 'true'},
            headers={'User-Agent': self.useragent},
            cookies={'sdkVersion': '3.8.6', 'deviceId': self.client_id},
        )
        try:
            auth = json.loads(response.text.replace('&&&START&&&', '')) or {}
        except Exception as exc:
            raise MiCloudException(f'Error getting xiaomi login sign. Cannot parse response. {exc}')
        return auth

    def _login_step2(self, captcha=None, **kwargs):
        url = f'{ACCOUNT_BASE}/pass/serviceLoginAuth2'
        post = {
            'user': self.username,
            'hash': hashlib.md5(self.password.encode()).hexdigest().upper(),
            'callback': kwargs.get('callback') or '',
            'sid': kwargs.get('sid') or self.sid,
            'qs': kwargs.get('qs') or '',
            '_sign': kwargs.get('_sign') or '',
        }
        params = {'_json': 'true'}
        headers = {'User-Agent': self.useragent}
        cookies = {'sdkVersion': '3.8.6', 'deviceId': self.client_id}
        if captcha:
            post['captCode'] = captcha
            params['_dc'] = int(time.time() * 1000)
            cookies['ick'] = self.attrs.pop('captchaIck', '')
        response = self.session.post(url, data=post, params=params, headers=headers, cookies=cookies)
        auth = json.loads(response.text.replace('&&&START&&&', '')) or {}
        code = auth.get('code')
        # 20003 InvalidUserNameException
        # 22009 PackageNameDeniedException
        # 70002 InvalidCredentialException
        # 70016 InvalidCredentialException with captchaUrl
        # 81003 NeedVerificationException
        # 87001 InvalidResponseException captCode error
        # other NeedCaptchaException
        location = auth.get('location')
        if not location:
            if cap := auth.get('captchaUrl'):
                if cap[:4] != 'http':
                    cap = f'{ACCOUNT_BASE}{cap}'
                if self._get_captcha(cap):
                    self.attrs['login_data'] = kwargs
            if ntf := auth.get('notificationUrl'):
                if ntf[:4] != 'http':
                    ntf = f'{ACCOUNT_BASE}{ntf}'
                self.attrs['notificationUrl'] = ntf
            _LOGGER.error('Xiaomi serviceLoginAuth2: %s', [url, params, post, headers, cookies])
            raise MiCloudAccessDenied(f'Login to xiaomi error: {response.text}')
        self.user_id = str(auth.get('userId', ''))
        self.cuser_id = auth.get('cUserId')
        self.ssecurity = auth.get('ssecurity')
        self.pass_token = auth.get('passToken')
        if self.sid != 'xiaomiio':
            sign = f'nonce={auth.get("nonce")}&{auth.get("ssecurity")}'
            sign = hashlib.sha1(sign.encode()).digest()
            sign = base64.b64encode(sign).decode()
            location += '&clientSign=' + parse.quote(sign)
        _LOGGER.debug('Xiaomi serviceLoginAuth2: %s', [auth, response.cookies.get_dict()])
        return location

    def _login_step3(self, location):
        self.session.headers.update({'content-type': 'application/x-www-form-urlencoded'})
        response = self.session.get(
            location,
            headers={'User-Agent': self.useragent},
            cookies={'sdkVersion': '3.8.6', 'deviceId': self.client_id},
        )
        service_token = response.cookies.get('serviceToken')
        if service_token:
            self.service_token = service_token
        else:
            err = {
                'location': location,
                'status_code': response.status_code,
                'cookies': response.cookies.get_dict(),
                'response': response.text,
            }
            raise MiCloudAccessDenied(f'Login to xiaomi error: {err}')
        return response

    def _get_captcha(self, url):
        response = self.session.get(url)
        if ick := response.cookies.get('ick'):
            self.attrs['captchaIck'] = ick
            self.attrs['captchaImg'] = base64.b64encode(response.content).decode()
        return response

    def api_session(self):
        if not self.service_token or not self.user_id:
            raise MiCloudException('Cannot execute request. service token or userId missing. Make sure to login.')

        session = requests.Session()
        session.headers.update({
            'X-XIAOMI-PROTOCAL-FLAG-CLI': 'PROTOCAL-HTTP2',
            'Content-Type': 'application/x-www-form-urlencoded',
            'User-Agent': self.useragent,
        })
        session.cookies.update({
            'userId': str(self.user_id),
            'yetAnotherServiceToken': self.service_token,
            'serviceToken': self.service_token,
            'locale': str(self.locale),
            'timezone': str(self.timezone),
            'is_daylight': str(time.daylight),
            'dst_offset': str(time.localtime().tm_isdst * 60 * 60 * 1000),
            'channel': 'MI_APP_STORE',
        })
        return session

    def request(self, url, params, **kwargs):
        self.session = self.api_session()
        timeout = kwargs.get('timeout', self.http_timeout)
        try:
            nonce = miutils.gen_nonce()
            signed_nonce = miutils.signed_nonce(self.ssecurity, nonce)
            signature = miutils.gen_signature(url.replace('/app/', '/'), signed_nonce, nonce, params)
            post_data = {
                'signature': signature,
                '_nonce': nonce,
                'data': params['data'],
            }
            response = self.session.post(url, data=post_data, timeout=timeout)
            return response.text
        except requests.exceptions.HTTPError as exc:
            _LOGGER.error('Error while executing request to %s: %s', url, exc)
        except MiCloudException as exc:
            _LOGGER.error('Error while decrypting response of request to %s: %s', url, exc)

    def request_rc4_api(self, api, params: dict, method='POST', **kwargs):
        self.session = self.api_session()
        self.session.headers.update({
            'MIOT-ENCRYPT-ALGORITHM': 'ENCRYPT-RC4',
            'Accept-Encoding': 'identity',
        })
        url = self.get_api_url(api)
        timeout = kwargs.get('timeout', self.http_timeout)
        try:
            params = self.rc4_params(method, url, params)
            signed_nonce = self.signed_nonce(params['_nonce'])
            if method == 'GET':
                response = self.session.get(url, params=params, timeout=timeout)
            else:
                response = self.session.post(url, data=params, timeout=timeout)
            rsp = response.text
            if not rsp or 'error' in rsp or 'invalid' in rsp:
                _LOGGER.warning('Error while executing request to %s: %s', url, rsp or response.status_code)
            elif 'message' not in rsp:
                try:
                    rsp = MiotCloud.decrypt_data(signed_nonce, rsp)
                except ValueError:
                    _LOGGER.warning('Error while decrypting response of request to %s :%s', url, rsp)
            return rsp
        except requests.exceptions.HTTPError as exc:
            _LOGGER.warning('Error while executing request to %s: %s', url, exc)
        except MiCloudException as exc:
            _LOGGER.warning('Error while decrypting response of request to %s :%s', url, exc)

    def request_raw(self, url, data=None, method='GET', **kwargs):
        self.session = self.api_session()
        url = self.get_api_url(url)
        kwargs.setdefault('params' if method == 'GET' else 'data', data)
        kwargs.setdefault('timeout', self.http_timeout)
        try:
            response = self.session.request(method, url, **kwargs)
            if response.status_code == 401:
                self._logout()
                _LOGGER.warning('Unauthorized while executing request to %s, logged out.', url)
            rsp = response.text
            if not rsp or 'error' in rsp or 'invalid' in rsp:
                log = _LOGGER.info if 'remote/ubus' in url else _LOGGER.warning
                log('Error while executing request to %s: %s', url, rsp or response.status_code)
            return rsp
        except requests.exceptions.HTTPError as exc:
            _LOGGER.warning('Error while executing request to %s: %s', url, exc)
        return None

    def get_api_by_host(self, host, api=''):
        srv = self.default_server.lower()
        if srv and srv != 'cn':
            host = f'{srv}.{host}'
        api = str(api).lstrip('/')
        return f'https://{host}/{api}'

    def get_api_url(self, api):
        if api[:6] == 'https:' or api[:5] == 'http:':
            url = api
        else:
            api = str(api).lstrip('/')
            url = self._get_api_url(self.default_server) + '/' + api
        return url

    def rc4_params(self, method, url, params: dict):
        nonce = miutils.gen_nonce()
        signed_nonce = self.signed_nonce(nonce)
        params['rc4_hash__'] = MiotCloud.sha1_sign(method, url, params, signed_nonce)
        for k, v in params.items():
            params[k] = MiotCloud.encrypt_data(signed_nonce, v)
        params.update({
            'signature': MiotCloud.sha1_sign(method, url, params, signed_nonce),
            'ssecurity': self.ssecurity,
            '_nonce': nonce,
        })
        return params

    def signed_nonce(self, nonce):
        return miutils.signed_nonce(self.ssecurity, nonce)

    @staticmethod
    def json_encode(data):
        return json.dumps(data, separators=(',', ':'))

    @staticmethod
    def sha1_sign(method, url, dat: dict, nonce):
        path = parse.urlparse(url).path
        if path[:5] == '/app/':
            path = path[4:]
        arr = [str(method).upper(), path]
        for k, v in dat.items():
            arr.append(f'{k}={v}')
        arr.append(nonce)
        raw = hashlib.sha1('&'.join(arr).encode('utf-8')).digest()
        return base64.b64encode(raw).decode()

    @staticmethod
    def encrypt_data(pwd, data):
        return base64.b64encode(RC4(base64.b64decode(pwd)).init1024().crypt(data)).decode()

    @staticmethod
    def decrypt_data(pwd, data):
        return RC4(base64.b64decode(pwd)).init1024().crypt(base64.b64decode(data))

    @staticmethod
    def get_random_string(length):
        seq = string.ascii_uppercase + string.digits
        return ''.join((random.choice(seq) for _ in range(length)))
