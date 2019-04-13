#!/usr/bin/env python

import abc
import json
import datetime
import logging
import hashlib
import uuid
from optparse import OptionParser
from http.server import HTTPServer, BaseHTTPRequestHandler

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

    def __init__(self, required, nullable):
        self.required = required
        self.nullable = nullable


class CharField(Field):

    def __init__(self, required, nullable):
        super().__init__(self, required, nullable)


class ArgumentsField(Field):

    def __init__(self, required, nullable):
        super().__init__(self, required, nullable)


class EmailField(CharField):

    def __init__(self, required, nullable):
        super().__init__(self, required, nullable)


class PhoneField(Field):

    def __init__(self, required, nullable):
        super().__init__(self, required, nullable)


class DateField(Field):

    def __init__(self, required, nullable):
        super().__init__(self, required, nullable)


class BirthDayField(Field):

    def __init__(self, required, nullable):
        super().__init__(self, required, nullable)


class GenderField(Field):

    def __init__(self, required, nullable):
        super().__init__(self, required, nullable)


class ClientIDsField(Field):

    def __init__(self, required, nullable):
        super().__init__(self, required, nullable)


class MethodRequest:

    def __init__(self):
        self.account = CharField(required=False, nullable=True)
        self.login = CharField(required=True, nullable=True)
        self.token = CharField(required=True, nullable=True)
        self.arguments = ArgumentsField(required=True, nullable=True)
        self.method = CharField(required=True, nullable=False)

    @property
    def is_admin(self):
        return self.login == ADMIN_LOGIN

    def method_handler(self):
        pass


class ClientsInterestsRequest(MethodRequest):

    def __init__(self):
        super().__init__(self)
        self.client_ids = ClientIDsField(required=True)
        self.date = DateField(required=False, nullable=True)

    def method_handler(self):
        pass


class OnlineScoreRequest(MethodRequest):

    def __init__(self):
        super().__init__(self)
        self.first_name = CharField(required=False, nullable=True)
        self.last_name = CharField(required=False, nullable=True)
        self.email = EmailField(required=False, nullable=True)
        self.phone = PhoneField(required=False, nullable=True)
        self.birthday = BirthDayField(required=False, nullable=True)
        self.gender = GenderField(required=False, nullable=True)

    def method_handler(self):
        pass

def check_auth(request):
    if request.is_admin:
        digest = hashlib.sha512(datetime.datetime.now().strftime("%Y%m%d%H") + ADMIN_SALT).hexdigest()
    else:
        digest = hashlib.sha512(request.account + request.login + SALT).hexdigest()
    if digest == request.token:
        return True
    return False


def method_handler(request, ctx, store):
    response, code = None, None
    return response, code


class MainHTTPHandler(BaseHTTPRequestHandler):
    router = {
        'method': method_handler
    }
    store = None

    def get_request_id(self, headers):
        return headers.get('HTTP_X_REQUEST_ID', uuid.uuid4().hex)

    def do_POST(self):
        response, code = {}, OK
        context = {"request_id": self.get_request_id(self.headers)}
        request = None
        try:
            data_string = self.rfile.read(int(self.headers['Content-Length']))
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
