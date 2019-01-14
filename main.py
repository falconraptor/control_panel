from _csv import reader

from pam import pam

from webserver import start_with_args, route
from webserver.server import Request, serve


GROUPS = {}
USERS = {}
USER_GROUPS = {}
GROUP_USERS = {}


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
            request.set_session('auth', request.POST['username'], path='/', http_only=True, secure=True, domain='panel.techraptor.us')
            refresh_users()
            return '', 303, {'Location': request.GET.get('next', '/')}
    elif 'auth' in request.COOKIE:
        return '', 303, {'Location': request.GET.get('next', '/')}
    return serve('html/login.html')


def refresh_users():
    global USERS, GROUPS, USER_GROUPS, GROUP_USERS
    with open('/etc/passwd') as _in:
        USERS = {}
        for row in reader(_in, delimiter=':'):
            name = row[4].split(',')
            l_name = len(name)
            USERS[row[0]] = {'home': row[5], 'terminal': row[6], 'username': row[0], 'name': name[0], 'room': name[1] if l_name > 1 else '', 'office phone': name[2] if l_name > 2 else '', 'home phone': name[3] if l_name > 3 else '', 'other': name[4:]}
        USER_GROUPS = {u: set() for u in USERS}
    with open('/etc/group') as _in:
        GROUPS = {}
        for row in reader(_in, delimiter=':'):
            GROUPS[row[0]] = {'group': row[0]}
            for u in row[3].split(','):
                if not u:
                    continue
                try:
                    GROUP_USERS[row[0]][u] = USERS[u]
                except KeyError:
                    GROUP_USERS[row[0]] = {u: USERS[u]}
                USER_GROUPS[u].add(row[0])


@route(methods=['GET'])
@auth
def index(request):
    return serve('html/index.html')


@route(methods=['GET'])
def logout(request):
    request.set_cookie('auth', value='', max_age=0, path='/', http_only=True, secure=True, domain='panel.techraptor.us')
    return '', 303, {'Location': '/login/'}


@route(methods=['GET'])
@auth
def ajax(request):
    if not USERS:
        refresh_users()
    results = {}
    user = request.COOKIE['auth'].value
    if request.GET.get('get', '') == 'self':
        results['user'] = USERS[user]
        results['groups'] = sorted(USER_GROUPS[user])
    return results


if __name__ == '__main__':
    start_with_args(bind_default='127.0.0.1', cors_methods=['POST'])
