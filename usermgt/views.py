from django.shortcuts import render
from django.http import HttpResponseRedirect, HttpResponse
from django.views.decorators.csrf import csrf_exempt, csrf_protect
from usermgt.forms import LoginFrom


@csrf_exempt
def login(request):
    if request.method == 'POST':
        form = LoginFrom(request.POST)
        if form.is_valid():
            print(form.cleaned_data)
            username = form.cleaned_data.get('user_dn')
            request.session['username'] = username
            return HttpResponseRedirect('/index/')
        print(form.errors)
    else:
        form = LoginFrom()
    return render(request, 'login.html', {'uf': form})


def index(request):
    username = request.session.get('username')
    print(username)
    if username:
        return render(request, 'index.html', {'username': username})
    return render(request, 'login.html')


def change_pwd(request):
    pass

