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

    def __init__(self, required, nullable, key, value):
        self._required = required
        self._nullable = nullable
        self._key = key
        self._value = value


    @property
    def required(self):
        return self._required

    @property
    def nullable(self):
        return self._nullable

    def validate(self):
        raise NotImplementedError

    @property
    def key(self):
        return self._key

    @property
    def value(self):
        return self._value

    @value.setter
    def set_value(self, value):
        self._value = value


class CharField(Field):

    def __init__(self, required, nullable, key, value):
        super().__init__(self, required, nullable, key, value)

    def validate(self):
        return isinstance(self.value, str)


class ArgumentsField(Field):

    def __init__(self, required, nullable, key, value):
        super().__init__(self, required, nullable, key, value)

    def validate(self):
        try:
            arguments = json.load(self.value)
        except ValueError as e:
            logging.exception(e)
            return False
        return isinstance(arguments, dict)


class EmailField(CharField):

    def __init__(self, required, nullable, key, value):
        super().__init__(self, required, nullable, 'email', value)

    def validate(self):
        return super().validate() and '@' in self.value


class PhoneField(Field):

    def __init__(self, required, nullable):
        super().__init__(self, required, nullable)

    def validate(self):
        if isinstance(self.value, str) or isinstance(self.value, int):
            if len(str(self.value)) == 11 and str(self.value)[0] == '7':
                return False
            else:
                return True
        else:
            return False


class DateField(CharField):

    def __init__(self, required, nullable):
        super().__init__(self, required, nullable)

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

    def __init__(self, required, nullable, key, value):
        super().__init__(self, required, nullable, 'birthday', value)

    def validate(self):
        if super().validate() is False:
            return False

        date = datetime.strptime(self.value, '%d.%m.%Y')
        now = datetime.now()
        if now - date > datetime.fromtimestamp(YEAR*AGE):
            return False
        return True


class GenderField(Field):

    def __init__(self, required, nullable):
        super().__init__(self, required, nullable)

    def validate(self):
        return isinstance(self.value, int) and self.value in GENDERS


class ClientIDsField(Field):

    def __init__(self, required, nullable):
        super().__init__(self, required, nullable)

    def validate(self):
        if isinstance(self.value, list):
            for client_id in self.value:
                if isinstance(client_id, int) is False:
                    return False
        else:
            return False
        return True


class Request:
    class Fields:
        def __init__(self):
            self._fields = []

        def __getitem__(self, key):
            return self._fields[key]

        def __setitem__(self, key, value):
            self._fields[key] = value

    def __init__(self):
        self.fields = Request.Fields()

    def __call__(self, data, ctx, store):
        if check_auth() is False:
            raise Exception(ERRORS[FORBIDDEN])
        self._parse(data)
        if self._validate(data) is False:
            raise Exception(ERRORS[INVALID_REQUEST])
        return self.method_handler(data, ctx, store)

    def parse(self, arguments):
        for key, value in self.fields:
            if key in arguments:
                self.fields[key] = arguments[key]

    def validate(self, arguments):
        for key, value in self.fields:
            if value.required and key not in arguments \
                    or \
                    value.nullable is False and key in arguments and arguments[key] is None \
                    or \
                    key in arguments and value.validate() is False:
                return False
        return True

    def method_handler(self, request, ctx, store):
        raise NotImplementedError

    @property
    def is_admin(self):
        raise NotImplementedError


class MethodRequest(Request):

    def __init__(self):
        super().__init__(self)
        self.fields['account'] = CharField(required=False, nullable=True)
        self.fields['login'] = CharField(required=True, nullable=True)
        self.fields['token'] = CharField(required=True, nullable=True)
        self.fields['arguments'] = ArgumentsField(required=True, nullable=True)
        self.fields['method'] = CharField(required=True, nullable=False)

    def __call__(self, request, ctx, store):
        if check_auth() is False:
            raise Exception(ERRORS[FORBIDDEN])
        self.parse(request['body'])
        if self.validate(request['body']) is False:
            raise Exception(ERRORS[INVALID_REQUEST])
        return self.method_handler(request, ctx, store)



    @property
    def is_admin(self):
        return self.fields['login'] == ADMIN_LOGIN

    def method_handler(self, request, ctx, store):
        raise NotImplementedError


class ClientsInterestsRequest(Request):

    def __init__(self):
        super().__init__(self)
        self._request = MethodRequest()
        self.fields['client_ids'] = ClientIDsField(required=True)
        self.fields['date'] = DateField(required=False, nullable=True)

    def __call__(self, request, ctx, store):
        self._request

    def method_handler(self, data, ctx, store):
        response = {}
        ctx['nclients'] = len(self.fields['client_ids'])
        for cid in self.fields['client_ids']:
            response[cid] = scoring.get_interests(store, cid)
        return response


class OnlineScoreRequest(Request):

    def __init__(self):
        super().__init__()
        self.fields['first_name'] = CharField(required=False, nullable=True)
        self.fields['last_name'] = CharField(required=False, nullable=True)
        self.fields['email'] = EmailField(required=False, nullable=True)
        self.fields['phone'] = PhoneField(required=False, nullable=True)
        self.fields['birthday'] = BirthDayField(required=False, nullable=True)
        self.fields['gender'] = GenderField(required=False, nullable=True)

    def method_handler(self, data, ctx, store):
        ctx['has'] = []
        for key, value in self.fields:
            if value is not None:
                ctx['has'].append(value)
        if self.is_admin:
            return ADMIN_SALT
        else:
            return scoring.get_score(store, self.phone, self.email, self.birthday, self.gender, self.first_name,
                                     self.last_name)


def check_auth(request):
    if request.is_admin:
        digest = hashlib.sha512(datetime.now().strftime('%Y%m%d%H') + ADMIN_SALT).hexdigest()
    else:
        digest = hashlib.sha512(request.account + request.login + SALT).hexdigest()
    if digest == request.token:
        return True
    return False


def method_handler(request, ctx, store):
    response, code = None, None
    handlers = {'scoring': OnlineScoreRequest,
                'clients_interests': ClientsInterestsRequest}
    if request['body']['method'] in handlers:
        response, code = handlers[request['body']['method']](request, ctx, store)
    return response, code


class MainHTTPHandler(BaseHTTPRequestHandler):
    router = {
        'method': method_handler
    }
    store = None

    @staticmethod
    def get_request_id(headers):
        return headers.get('HTTP_X_REQUEST_ID', uuid.uuid4().hex)

    def do_post(self):
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

        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        if code not in ERRORS:
            r = {'response': response, 'code': code}
        else:
            r = {'error': response or ERRORS.get(code, 'Unknown Error'), 'code': code}
        context.update(r)
        logging.info(context)
        self.wfile.write(json.dumps(r))
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
