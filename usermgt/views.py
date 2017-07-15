from django.shortcuts import render
from django.http import HttpResponseRedirect, HttpResponse
from django.views.decorators.csrf import csrf_exempt, csrf_protect
from usermgt.forms import LoginFrom
from usermgt.adhandler import ADhandler


@csrf_exempt
def login(request):
    if request.method == 'POST':
        form = LoginFrom(request.POST)
        if form.is_valid():
            print(form.cleaned_data)
            username = form.cleaned_data.get('user_id')
            request.session['username'] = username
            return HttpResponseRedirect('/index/')
        print(form.errors)
    else:
        form = LoginFrom()
    return render(request, 'login.html', {'uf': form})


def index(request):
    username = request.session.get('username', False)
    if username:
        ad = ADhandler()
        data = ad.get_user_status(username)
        return render(request, 'index.html', {'data': data})
    return render(request, 'login.html')


def logout(request):
    try:
        del request.session['username']
    except KeyError:
        pass
    return HttpResponse("你已退出登录!")


def change_pwd(request):
    username = request.session.get('username', False)
    if username:

        ad = ADhandler()
        data = ad.get_user_status(username)
        return render(request, 'changepwd.html', {'data': data})
    return render(request, 'login.html')

