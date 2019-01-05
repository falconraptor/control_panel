from pam import pam

from webserver import start_with_args, route
from webserver.server import Request, serve


def auth(f):  # TODO use as template? User form auth instead
    def wrapped(*args, **kwargs):
        request = kwargs.get('request', args[0] if args else Request())
        if 'auth' not in request.COOKIE:
            return '', 303, {'Location': '/login/?next=' + request.PATH_INFO}
        return f(*args, **kwargs)
    wrapped.__name__ = f.__name__
    return wrapped


@route(methods=['GET', 'POST'])
def login(request):
    if request.REQUEST_METHOD == 'POST':
        if pam().authenticate(request.POST['username'], request.POST['password']):
            request.set_session('auth', '', path='/', http_only=True, secure=True)
            return '', 303, {'Location': request.GET.get('next', '/')}
    return serve('html/login.html')


@route(methods=['GET'])
@auth
def index(request):
    return serve('html/index.html')


@route(methods=['GET'])
def logout(request):
    request.set_cookie('auth', value='', max_age=1, path='/', http_only=True, secure=True)
    return '', 303, {'Location': '/login/'}


if __name__ == '__main__':
    start_with_args(bind_default='127.0.0.1')
