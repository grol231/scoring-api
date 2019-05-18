#!/usr/bin/env python

import json
import datetime
import logging
import hashlib
import uuid
from optparse import OptionParser
from http.server import HTTPServer, BaseHTTPRequestHandler
import scoring

YEAR = 31536000
AGE = 70
SALT = "Otus"
ADMIN_LOGIN = "admin"
ADMIN_SALT = "42"
OK = 200
BAD_REQUEST = 400
FORBIDDEN = 403
NOT_FOUND = 404
INVALID_REQUEST = 422
INTERNAL_ERROR = 500
ERRORS = {
    BAD_REQUEST: "Bad Request",
    FORBIDDEN: "Forbidden",
    NOT_FOUND: "Not Found",
    INVALID_REQUEST: "Invalid Request",
    INTERNAL_ERROR: "Internal Server Error",
}
UNKNOWN = 0
MALE = 1
FEMALE = 2
GENDERS = {
    UNKNOWN: "unknown",
    MALE: "male",
    FEMALE: "female",
}


class Field:
    def __init__(self, required, nullable=False):
        self.required = required
        self.nullable = nullable
        self.value = None

    def __get__(self, obj, objtype=None):
        return self.value

    def __set__(self, obj, value):
        self.value = value

    def __add__(self, field):
        return self.value + field.value

    def __eq__(self, other):
        return self.value == other

    def is_required(self):
        return self.required

    def is_nullable(self):
        return self.nullable

    def validate(self):
        raise NotImplementedError("you need to define a validate method")


class CharField(Field):
    def validate(self):
        if isinstance(self.value, str) is False:
            raise ValueError('char field is not str')


class ArgumentsField(Field):
    def validate(self):
        if isinstance(self.value, dict) is False:
            raise ValueError('arguments field is not dict')


class EmailField(CharField):
    def validate(self):
        super().validate()
        if '@' not in self.value:
            raise ValueError('email field must have @')


class PhoneField(Field):
    def validate(self):
        if (isinstance(self.value, str) or isinstance(self.value, int)) is False:
            raise ValueError('phone field is not str or int')
        if len(str(self.value)) != 11:
            raise ValueError('phone field must have 11 numbers')
        if str(self.value)[0] != '7':
            raise ValueError('phone field must have 7 in the begin')


class DateField(CharField):
    def validate(self):
        super().validate()
        try:
            datetime.datetime.strptime(self.value, '%d.%m.%Y')
        except ValueError:
            raise ValueError('Incorrect data format, should be DD.MM.YYYY')


class BirthDayField(DateField):
    def validate(self):
        super().validate()
        date = datetime.datetime.strptime(self.value, '%d.%m.%Y')
        now = datetime.datetime.now()
        diff = int((now - date).total_seconds())
        if diff > int(datetime.datetime.fromtimestamp(YEAR*AGE).timestamp()):
            raise ValueError('age must be less than 70 years')


class GenderField(Field):
    def validate(self):
        if isinstance(self.value, int) is False:
            raise ValueError('gender field must be int')
        if self.value not in GENDERS:
            raise ValueError('gender field must be to equal 0,1,2')


class ClientIDsField(Field):
    def validate(self):
        if isinstance(self.value, list) is False:
            raise ValueError('client ids field must be list')
        if len(self.value) <= 0:
            raise ValueError('client ids field must be more than 0')
        for client_id in self.value:
            if isinstance(client_id, int) is False:
                raise ValueError('client ids field element must be int')


class MetaRequest(type):
    def __new__(mcs, name, base, attrs):
        fields = {}
        for key, value in attrs.items():
            if isinstance(value, Field):
                fields[key] = value
        attrs['fields'] = fields
        return type.__new__(mcs, name, base, attrs)


class BaseRequest:
    def parse(self, body):
        for key in self.fields:
            if self.fields[key].required and key not in body:
                raise ValueError('invalid request: required field {}'.format(key))
            if self.fields[key].nullable is False and key in body and (body[key] is None or len(body[key]) == 0):
                raise ValueError('invalid request: field {} must have value'.format(key))
            if key in body:
                self.fields[key] = body[key]
                logging.info('{} : {}'.format(key, body[key]))
        logging.info('parse finished')

    def validate(self):
        for key in self.fields:
            if self.fields[key]:
                self.fields[key].validate()
        logging.info('validation finished')


class AuthMixin:
    auth = None

    @property
    def auth(self):
        return self.auth

    @auth.setter
    def auth(self, auth):
        self.auth = auth

    @property
    def is_admin(self):
        return self.auth if self.auth.is_admin else False


class ClientsInterestsRequest(BaseRequest, AuthMixin, metaclass=MetaRequest):
    client_ids = ClientIDsField(required=True)
    date = DateField(required=False, nullable=True)

    @classmethod
    def from_raw_request(cls, request):
        obj = cls()
        obj.parse(request)
        return obj

    def handle(self, request, ctx, store):
        response = {}
        ctx['nclients'] = len(self.client_ids)
        for cid in self.client_ids:
            response[cid] = scoring.get_interests(store, cid)
        return response, OK


class OnlineScoreRequest(BaseRequest, AuthMixin, metaclass=MetaRequest):
    first_name = CharField(required=False, nullable=True)
    last_name = CharField(required=False, nullable=True)
    email = EmailField(required=False, nullable=True)
    phone = PhoneField(required=False, nullable=True)
    birthday = BirthDayField(required=False, nullable=True)
    gender = GenderField(required=False, nullable=True)

    #def __init__(self):
     #   for key, field in self.fields.items():# this does not work!!!!!!!!!!!!!!!!!!!!!!111
      #      field = None

    @classmethod
    def from_raw_request(cls, request):
        obj = cls()
        obj.parse(request['body']['arguments'])
        obj.validate()
        return obj

    def validate_dependencies(self):
        if (self.phone is not None and self.email is not None\
                or self.first_name is not None and self.last_name is not None\
                or self.gender is not None and self.birthday is not None) is False:
            raise ValueError('invalid dependencies of online score method')

    def handle(self, request, ctx, store):
        self.validate_dependencies()
        ctx['has'] = []
        for key, field in self.fields.items():
            if field or isinstance(field, int) and field == 0:
                ctx['has'].append(key)
        if request.is_admin:
            score = int(ADMIN_SALT)
        else:
            score = scoring.get_score(store, self.phone, self.email, self.birthday, self.gender, self.first_name,
                                      self.last_name)
        response = {'score': score}
        return response, OK


class MethodRequest(BaseRequest, metaclass=MetaRequest):
    account = CharField(required=False, nullable=True)
    login = CharField(required=True, nullable=True)
    token = CharField(required=True, nullable=True)
    arguments = ArgumentsField(required=True, nullable=True)
    method = CharField(required=True, nullable=False)

    @classmethod
    def from_raw_request(cls, request):
        obj = cls()
        obj.parse(request['body'])
        obj.validate()
        return obj

    @property
    def is_admin(self):
        return self.login == ADMIN_LOGIN


def check_auth(request):
    if request.is_admin:
        digest = hashlib.sha512(bytes(datetime.datetime.now().strftime("%Y%m%d%H") + ADMIN_SALT, 'utf-8')).hexdigest()
    else:
        digest = hashlib.sha512(bytes(request.account + request.login + SALT, 'utf-8')).hexdigest()
    if digest == request.token:
        return True
    return False


def online_score_handler(request, ctx, store):
    request.validate_dependencies()
    ctx['has'] = []
    for key, field in request.fields.items():
        if field or isinstance(field, int) and field == 0:
            ctx['has'].append(key)
    r = MethodRequest.from_raw_request(request)
    if r.is_admin:
        score = int(ADMIN_SALT)
    else:
        score = scoring.get_score(store, request.phone, request.email, request.birthday, request.gender, 
                                  request.first_name, request.last_name)
    response = {'score': score}
    return response, OK


def clients_interests_handler(request, ctx, store):
    response = {}
    ctx['nclients'] = len(request.client_ids)
    for cid in request.client_ids:
        response[cid] = scoring.get_interests(store, cid)
    return response, OK


def method_handler(request, ctx, store):
    try:
        auth = MethodRequest.from_raw_request(request)
        if check_auth(auth) is False:
            return None, FORBIDDEN

        methods = {
            'online_score': {'request': OnlineScoreRequest, 'handler': online_score_handler},
            'clients_interests': {'request': ClientsInterestsRequest, 'handler': clients_interests_handler}
        }
        url = request['body']['method']
        if url in methods:
            r = methods[url]['request'].from_raw_request(request)
            r.auth = auth
            return methods[url]['handler'](r, ctx, store)
        else:
            return None, NOT_FOUND

    except ValueError as e:
        logging.exception(e) #TODO: must be error
        return None, INVALID_REQUEST
    # except Exception as e:
    #     logging.exception(e)
    #     response = ERRORS[FORBIDDEN]
    #     code = FORBIDDEN
    #     return response, code


class MainHTTPHandler(BaseHTTPRequestHandler):
    router = {
        "method": method_handler
    }
    store = None

    def get_request_id(self, headers):
        return headers.get('HTTP_X_REQUEST_ID', uuid.uuid4().hex)

    def do_POST(self):
        response, code = {}, OK
        context = {"request_id": self.get_request_id(self.headers)}
        request = None
        try:
            data_string = self.rfile.read(int(self.headers['Content-Length'])).decode('utf-8')
            request = json.loads(data_string)
        except:
            code = BAD_REQUEST

        if request:
            path = self.path.strip("/")
            logging.info("%s: %s %s" % (self.path, data_string, context["request_id"]))
            if path in self.router:
                try:
                    response, code = self.router[path]({"body": request, "headers": self.headers}, context, self.store)
                except Exception as e:
                    logging.exception("Unexpected error: %s" % e)
                    code = INTERNAL_ERROR
            else:
                code = NOT_FOUND

        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        if code not in ERRORS:
            r = {"response": response, "code": code}
        else:
            r = {"error": response or ERRORS.get(code, "Unknown Error"), "code": code}
        context.update(r)
        logging.info(context)
        self.wfile.write(json.dumps(r))
        return


if __name__ == "__main__":
    op = OptionParser()
    op.add_option("-p", "--port", action="store", type=int, default=8080)
    op.add_option("-l", "--log", action="store", default=None)
    (opts, args) = op.parse_args()
    logging.basicConfig(filename=opts.log, level=logging.INFO,
                        format='[%(asctime)s] %(levelname).1s %(message)s', datefmt='%Y.%m.%d %H:%M:%S')
    server = HTTPServer(("localhost", opts.port), MainHTTPHandler)
    logging.info("Starting server at %s" % opts.port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.server_close()
