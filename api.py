#!/usr/bin/env python

import json
from datetime import datetime
import logging
import hashlib
import uuid
from optparse import OptionParser
from http.server import HTTPServer, BaseHTTPRequestHandler
import scoring

SALT = 'Otus'
ADMIN_LOGIN = 'admin'
ADMIN_SALT = '42'
OK = 200
YEAR = 31536000
AGE = 70
BAD_REQUEST = 400
FORBIDDEN = 403
NOT_FOUND = 404
INVALID_REQUEST = 422
INTERNAL_ERROR = 500
ERRORS = {
    BAD_REQUEST: 'Bad Request',
    FORBIDDEN: 'Forbidden',
    NOT_FOUND: 'Not Found',
    INVALID_REQUEST: 'Invalid Request',
    INTERNAL_ERROR: 'Internal Server Error',
}
UNKNOWN = 0
MALE = 1
FEMALE = 2
GENDERS = {
    UNKNOWN: 'unknown',
    MALE: 'male',
    FEMALE: 'female',
}


class Field:

    def __init__(self, required, nullable=False):
        self._required = required
        self._nullable = nullable
        self._value = None


    @property
    def required(self):
        return self._required

    @property
    def nullable(self):
        return self._nullable

    def validate(self):
        raise NotImplementedError

    @property
    def value(self):
        return self._value

    @value.setter
    def value(self, value):
        self._value = value


class CharField(Field):

    def __init__(self, required, nullable):
        super().__init__(required, nullable)

    def validate(self):
        return isinstance(self.value, str)


class ArgumentsField(Field):

    def __init__(self, required, nullable):
        super().__init__(required, nullable)

    def validate(self):
        return isinstance(self.value, dict)


class EmailField(CharField):

    def __init__(self, required, nullable):
        super().__init__(required, nullable)

    def validate(self):
        return super().validate() and '@' in self.value


class PhoneField(Field):

    def __init__(self, required, nullable):
        super().__init__(required, nullable)

    def validate(self):
        if (isinstance(self.value, str) or isinstance(self.value, int)) and \
                len(str(self.value)) == 11 and str(self.value)[0] == '7':
                return True
        return False


class DateField(CharField):

    def __init__(self, required, nullable):
        super().__init__(required, nullable)

    def validate(self):
        if super().validate() is False:
            return False
        try:
            datetime.strptime(self.value, '%d.%m.%Y')
        except ValueError:
            logging.error('Incorrect data format, should be DD.MM.YYYY')
            return False
        return True


class BirthDayField(DateField):

    def __init__(self, required, nullable):
        super().__init__(required, nullable)

    def validate(self):
        if super().validate() is False:
            return False
        date = datetime.strptime(self.value, '%d.%m.%Y')
        now = datetime.now()
        diff = int((now - date).total_seconds())
        if diff > int(datetime.fromtimestamp(YEAR*AGE).timestamp()):
            return False
        return True


class GenderField(Field):

    def __init__(self, required, nullable):
        super().__init__(required, nullable)

    def validate(self):
        return isinstance(self.value, int) and self.value in GENDERS


class ClientIDsField(Field):

    def __init__(self, required):
        super().__init__(required)

    # def __len__(self):
    #     return len(self.value)

    def validate(self):
        if isinstance(self.value, list):
            for client_id in self.value:
                if isinstance(client_id, int) is False:
                    return False
        else:
            return False
        return True


class MethodRequest:

    def __init__(self):
        self._account = CharField(required=False, nullable=True)
        self._login = CharField(required=True, nullable=False)
        self._token = CharField(required=True, nullable=True)
        self._arguments = ArgumentsField(required=True, nullable=True)
        self._method = CharField(required=True, nullable=False)

    def handler(self, request, ctx, store):
        code = OK
        response = 'OK'
        self._parse(request['body'])
        if self.login.value is None or self.account.value is None:
            response = ERRORS[INVALID_REQUEST]
            code = INVALID_REQUEST
            return response, code
        if check_auth(self) is False:
            response = ERRORS[FORBIDDEN]
            code = FORBIDDEN
            return response, code
        if self._validate(request['body']) is False:
            response = ERRORS[INVALID_REQUEST]
            code = INVALID_REQUEST
        return response, code

    @property
    def is_admin(self):
        return self.login.value == ADMIN_LOGIN

    @property
    def account(self):
        return self._account

    @property
    def login(self):
        return self._login

    @property
    def token(self):
        return self._token

    @property
    def arguments(self):
        return self._arguments

    @property
    def method(self):
        return self._method

    def _parse(self, body):
        if 'account' in body:
            self._account.value = body['account']
        if 'login' in body:
            self._login.value = body['login']
        if 'token' in body:
            self._token.value = body['token']
        if 'arguments' in body:
            self._arguments.value = body['arguments']
        if 'method' in body:
            self._method.value = body['method']

    def _validate(self, body):
        if self.account.required and 'account' not in body \
                or \
                self.account.nullable is False and 'account' in body and body['account'] is None\
                or\
                'account' in body and self.account.validate() is False:
            return False
        if self.login.required and 'login' not in body \
                or \
                self.account.nullable is False and ('login' not in body or body['login'] is None)\
                or\
                'login' in body and self.login.validate() is False:
            return False
        if self.token.required and 'token' not in body \
                or \
                self.token.nullable is False and 'token' in body and body['token'] is None\
                or\
                'token' in body and self.token.validate() is False:
            return False
        if self.arguments.required and 'arguments' not in body \
                or \
                self.arguments.nullable is False and 'arguments' in body and body['arguments'] is None\
                or\
                'arguments' in body and self.arguments.validate() is False:
            return False
        if self.method.required and 'method' not in body \
                or \
                self.method.nullable is False and 'method' in body and body['method'] is None\
                or\
                'method' in body and self.method.validate() is False:
            return False
        return True


class ClientsInterestsRequest:

    def __init__(self):
        self._method_request = MethodRequest()
        self._client_ids = ClientIDsField(required=True)
        self._date = DateField(required=False, nullable=True)

    def handler(self, request, ctx, store):
        response, code = self._method_request.handler(request, ctx, store)
        if code != OK:
            return response, code
        self._parse(request['body']['arguments'])
        if self._validate(request['body']['arguments']) is False:
            response = ERRORS[INVALID_REQUEST]
            code = INVALID_REQUEST
            return response, code
        return self.method_handler(request, ctx, store)

    @property
    def client_ids(self):
        return self._client_ids

    @property
    def date(self):
        return self._date

    def _parse(self, arguments):
        if 'client_ids' in arguments:
            self._client_ids.value = arguments['client_ids']
        if 'date' in arguments:
            self._date.value = arguments['date']

    def _validate(self, body):
        if self.client_ids.required and 'client_ids' not in body \
                or \
                self.client_ids.nullable is False and 'client_ids' in body and (body['client_ids'] is None or
                                                                                len(body['client_ids']) == 0)\
                or\
                'client_ids' in body and self.client_ids.validate() is False:
            return False
        if self.date.required and 'date' not in body \
                or \
                self.date.nullable is False and 'date' in body and body['date'] is None\
                or\
                'date' in body and self.date.validate() is False:
            return False
        return True

    def method_handler(self, request, ctx, store):
        response = {}
        ctx['nclients'] = len(self.client_ids.value)
        for cid in self.client_ids.value:
            response[cid] = scoring.get_interests(store, cid)
        return response, OK


class OnlineScoreRequest:

    def __init__(self):
        self._method_request = MethodRequest()
        self._first_name = CharField(required=False, nullable=True)
        self._last_name = CharField(required=False, nullable=True)
        self._email = EmailField(required=False, nullable=True)
        self._phone = PhoneField(required=False, nullable=True)
        self._birthday = BirthDayField(required=False, nullable=True)
        self._gender = GenderField(required=False, nullable=True)

    def handler(self, request, ctx, store):
        response, code = self._method_request.handler(request, ctx, store)
        if code != OK:
            return response, code
        self._parse(request['body']['arguments'])
        if 'arguments' not in request['body'] or len(request['body']['arguments']) == 0\
                or self._validate(request['body']['arguments']) is False:
            response = ERRORS[INVALID_REQUEST]
            code = INVALID_REQUEST
            return response, code
        return self.method_handler(request, ctx, store)

    @property
    def first_name(self):
        return self._first_name

    @property
    def last_name(self):
        return self._last_name

    @property
    def email(self):
        return self._email

    @property
    def phone(self):
        return self._phone

    @property
    def birthday(self):
        return self._birthday

    @property
    def gender(self):
        return self._gender

    def _parse(self, arguments):
        if 'first_name' in arguments:
            self._first_name.value = arguments['first_name']
        if 'last_name' in arguments:
            self._last_name.value = arguments['last_name']
        if 'phone' in arguments:
            self._phone.value = arguments['phone']
        if 'email' in arguments:
            self._email.value = arguments['email']
        if 'birthday' in arguments:
            self._birthday.value = arguments['birthday']
        if 'gender' in arguments:
            self._gender.value = arguments['gender']

    def _validate(self, body):
        if self.first_name.required and 'first_name' not in body \
                or \
                self.first_name.nullable is False and 'first_name' in body and body['first_name'] is None\
                or\
                'first_name' in body and self.first_name.validate() is False:
            return False
        if self.last_name.required and 'last_name' not in body \
                or \
                self.last_name.nullable is False and 'last_name' in body and body['last_name'] is None\
                or\
                'last_name' in body and self.last_name.validate() is False:
            return False
        if self.email.required and 'email' not in body \
                or \
                self.email.nullable is False and 'email' in body and body['email'] is None\
                or\
                'email' in body and self.email.validate() is False:
            return False
        if self.phone.required and 'phone' not in body \
                or \
                self.phone.nullable is False and 'phone' in body and body['phone'] is None\
                or\
                'phone' in body and self.phone.validate() is False:
            return False
        if self.birthday.required and 'birthday' not in body \
                or \
                self.birthday.nullable is False and 'birthday' in body and body['birthday'] is None\
                or\
                'birthday' in body and self.birthday.validate() is False:
            return False
        if self.gender.required and 'gender' not in body \
                or \
                self.gender.nullable is False and 'gender' in body and body['gender'] is None\
                or\
                'gender' in body and self.gender.validate() is False:
            return False

        has_pair_phone_and_email = 'phone' in body and body['phone'] and len(str(body['phone'])) != 0 and self.phone.validate()\
            and 'email' in body and body['email'] and len(body['email']) != 0 and self.email.validate()

        has_pair_first_and_last_name = 'first_name' in body and body['first_name'] and len(body['first_name']) != 0 and\
                                       self.first_name.validate() and 'last_name' in body and body['last_name'] and\
                                       len(body['last_name']) and self.last_name.validate()

        has_pair_gender_and_birthday = 'birthday' in body and body['birthday'] and len(body['birthday']) != 0 and\
            self.birthday.validate() and 'gender' in body and self.gender.validate()

        if has_pair_phone_and_email or has_pair_first_and_last_name or has_pair_gender_and_birthday:
            return True
        else:
            return False

    def method_handler(self, request, ctx, store):
        ctx['has'] = []
        arguments = request['body']['arguments']
        if 'first_name' in arguments and arguments['first_name'] and len(arguments['first_name']) != 0:
            ctx['has'].append('first_name')
        if 'last_name' in arguments and arguments['last_name'] and len(arguments['last_name']) != 0:
            ctx['has'].append('last_name')
        if 'phone' in arguments and arguments['phone'] and len(str(arguments['phone'])) != 0:
            ctx['has'].append('phone')
        if 'birthday' in arguments and arguments['birthday'] and len(arguments['birthday']) != 0:
            ctx['has'].append('birthday')
        if 'email' in arguments and arguments['email'] and len(arguments['email']) != 0:
            ctx['has'].append('email')
        if 'gender' in arguments and arguments['gender'] is not None:
            ctx['has'].append('gender')
        if self._method_request.is_admin:
            score = int(ADMIN_SALT)
        else:
            score = scoring.get_score(store, self.phone, self.email, self.birthday, self.gender, self.first_name,
                                      self.last_name)
        response = {'score': score}
        return response, OK


def check_auth(request):
    if request.is_admin:
        digest = hashlib.sha512(bytes(datetime.now().strftime('%Y%m%d%H') + ADMIN_SALT, 'utf-8')).hexdigest()
    else:
        digest = hashlib.sha512(bytes(request.account.value, 'utf-8') + bytes(request.login.value, 'utf-8') +
                                bytes(SALT, 'utf-8')).hexdigest()

    if digest == request.token.value:
        return True
    return False


def method_handler(request, ctx, store):
    response, code = None, None
    handlers = {'online_score': OnlineScoreRequest,
                'clients_interests': ClientsInterestsRequest}

    if request and 'body' in request and 'method' in request['body'] and request['body']['method'] in handlers:
        response, code = handlers[request['body']['method']]().handler(request, ctx, store)
    else:
        response = ERRORS[INVALID_REQUEST]
        code = INVALID_REQUEST
    return response, code


class MainHTTPHandler(BaseHTTPRequestHandler):
    router = {
        'method': method_handler
    }
    store = None

    @staticmethod
    def get_request_id(headers):
        return headers.get('HTTP_X_REQUEST_ID', uuid.uuid4().hex)

    def do_POST(self):
        response, code = {}, OK
        context = {'request_id': self.get_request_id(self.headers)}
        request = None
        try:
            data_string = self.rfile.read(int(self.headers['Content-Length']))
            request = json.loads(data_string)
        except Exception as e:
            logging.exception(e)
            code = BAD_REQUEST

        if request:
            context['has'] = self.get_field_list(request)
            path = self.path.strip('/')
            logging.info('%s: %s %s' % (self.path, data_string, context['request_id']))
            if path in self.router:
                try:
                    response, code = self.router[path]({'body': request, 'headers': self.headers}, context, self.store)
                except Exception as e:
                    logging.exception('Unexpected error: %s' % e)
                    code = INTERNAL_ERROR
            else:
                code = NOT_FOUND
        else:
            self.send_response(INVALID_REQUEST)
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        if code not in ERRORS:
            r = {'response': response, 'code': code}
        else:
            r = {'error': response or ERRORS.get(code, 'Unknown Error'), 'code': code}
        context.update(r)
        logging.info(context)
        self.wfile.write(bytes(json.dumps(r), 'utf-8'))
        return


if __name__ == '__main__':
    op = OptionParser()
    op.add_option('-p', '--port', action='store', type=int, default=8080)
    op.add_option('-l', '--log', action='store', default=None)
    (opts, args) = op.parse_args()
    logging.basicConfig(filename=opts.log, level=logging.INFO,
                        format='[%(asctime)s] %(levelname).1s %(message)s', datefmt='%Y.%m.%d %H:%M:%S')
    server = HTTPServer(('localhost', opts.port), MainHTTPHandler)
    logging.info('Starting server at %s' % opts.port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.server_close()
