from pam import pam

from webserver import start_with_args, route
from webserver.server import Request, serve


def auth(f):  # TODO use as template? User form auth instead
    def wrapped(*args, **kwargs):
        request = kwargs.get('request', args[0] if args else Request())
        if 'auth' not in request.COOKIE:
            return '', 303, {'Location': '/login/'}
        return f(*args, **kwargs)
    wrapped.__name__ = f.__name__
    return wrapped


@route(methods=['GET', 'POST'])
def login(request):
    if request.method == 'POST':
        if pam().authenticate(request.GET['username'], request.GET['password']):
            request.set_session('auth', request.GET['username'])
    return serve('html/login.html')


@route()
@auth
def login(request):
    return serve('html/index.html')


if __name__ == '__main__':
    start_with_args(bind_default='127.0.0.1')
