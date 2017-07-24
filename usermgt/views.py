from django.shortcuts import render
from django.http import HttpResponseRedirect, HttpResponse
from django.views.decorators.csrf import csrf_exempt, csrf_protect
from usermgt.adhandler import ADhandler
from usermgt.sms import SendEmail
import logging
logger = logging.getLogger(__name__)


@csrf_exempt
def login(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        if not username or not password:
            result = {'code': '', 'code_info': '请输入用户名和密码！', 'data': ''}
            return render(request, 'login.html', {'result': result})
        try:
            ad = ADhandler()
            res = ad.user_authn(username, password)
            if res['code'] == '0':
                username = res['data'].get('user_id')
                request.session['username'] = username
                return HttpResponseRedirect('/index/')

            if res['code'] == '532':
                info = '账户%s密码过期需修改密码' % (res['data'].get('user_id'))
                res_dict = {'code': '532', 'code_info': info, 'data': res['data']}
                request.session['res_dict'] = res_dict
                return HttpResponseRedirect('/mustchangepwd/')
            if res['code'] == '773':
                info = '账户%s下次登录强制修改密码' % (res['data'].get('user_id'))
                res_dict = {'code': '773', 'code_info': info, 'data': res['data']}
                request.session['res_dict'] = res_dict
                return HttpResponseRedirect('/mustchangepwd/')
            else:
                code = res['code']
                ldapcodes = {'525': '账户不存在！',
                             '52e': '密码错误！',
                             '530': '该账户此时间段不允许登录！',
                             '531': '该账户此工作站不允许登录！',
                             '532': '密码过期',
                             '533': '账户被禁用，请联系管理员！',
                             '701': '账户已过期！',
                             '773': '下次登录强制修改密码！',
                             '775': '账户已被锁，请联系管理员！'}
                result = {'code': code, 'code_info': ldapcodes[code], 'data': res['data']}
                return render(request, 'login.html', {'result': result})
        except Exception as e:
            logger.error(e)
            raise e
    return render(request, 'login.html', )


def index(request):
    username = request.session.get('username', False)
    if username:
        ad = ADhandler()
        data = ad.get_user_status(username)
        print(request.path)
        return render(request, 'index.html', {'data': data})
    return render(request, 'login.html')


def logout(request):
    try:
        del request.session['username']
    except KeyError as e:
        logger.error(e)
        raise e
    return render(request, 'login.html')


def cancel(request):
    try:
        del request.session['res_dict']
    except KeyError as e:
        logger.error(e)
        raise e
    return render(request, 'login.html')

@csrf_exempt
def change_pwd(request):
    username = request.session.get('username', False)
    if username:
        ad = ADhandler()
        data = ad.get_user_status(username)
        print(data)
        if data['acct_pwd_policy']['pwd_complexity_enforced'] == 1:
            data['acct_pwd_policy']['pwd_complexity_enforced'] = '已启用'
        if data['acct_pwd_policy']['pwd_complexity_enforced'] == 0:
            data['acct_pwd_policy']['pwd_complexity_enforced'] = '未启用'
        max_exp_day = data['acct_pwd_policy']['pwd_ttl']/(24*60*60)
        data['acct_pwd_policy']['pwd_ttl'] = max_exp_day

        if request.method == 'POST':
            oldpwd = request.POST['oldpwd']
            newpwd = request.POST['newpwd']
            newpwd2 = request.POST['newpwd2']
            user = data['user_id']
            print(newpwd2)
            if not oldpwd or not newpwd or not newpwd2:
                err_msg = '密码不能为空'
                return render(request, 'changepwd.html', {'err_msg': err_msg, 'data': data})
            if newpwd != newpwd2:
                err_msg = "提示:输入的两次新密码不同!"
                return render(request, 'changepwd.html', {'err_msg': err_msg, 'data': data})

            ad = ADhandler()
            stat = ad.user_authn(username, oldpwd)
            # ldapcodes = {'525': 'user not found',
            #              '52e': 'invalid credentials',
            #              '530': 'user not permitted to logon at this time',
            #              '531': 'user not permitted to logon at this workstation',
            #              '532': 'password expired',
            #              '533': 'account disabled',
            #              '701': 'account expired',
            #              '773': 'forced expired password',
            #              '775': 'account locked'}
            if stat['code'] not in ['0', '532', '733']:
                err_msg = '旧密码验证错误！'
                return render(request, 'changepwd.html', {'err_msg': err_msg, 'data': data})
            ldapcodes = {'0': '修改密码成功, 请重新登录!',
                         '1001': '管理员账号不能通过此工具修改密码，请联系管理员！',
                         '1002': '此账户不能更改密码，请联系管理员！',
                         '1003': '新密码不符合长度要求！',
                         '1004': '新密码不符合复杂度要求！',
                         '1005': '新密码不能包含用户名！',
                         '1006': '新密码不能包含用户名!'}
            res = ad.set_pwd(user, newpwd)
            code = res['code']
            if code == '0':
                # username = data['data'].get('user_id')
                # request.session['username'] = username
                return render(request, 'finshed.html')
            err_msg = ldapcodes[code]
            return render(request, 'changepwd.html', {'err_msg': err_msg, 'data': data})
        return render(request, 'changepwd.html', {'data': data})
    return render(request, 'login.html')


@csrf_exempt
def must_change_pwd(request):
    res_dict = request.session.get('res_dict', False)
    if res_dict:
        data = res_dict

        if data['data']['acct_pwd_policy']['pwd_complexity_enforced'] == 1:
            data['data']['acct_pwd_policy']['pwd_complexity_enforced'] = '已启用'
        if data['data']['acct_pwd_policy']['pwd_complexity_enforced'] == 0:
            data['data']['acct_pwd_policy']['pwd_complexity_enforced'] = '未启用'
        max_exp_day = data['data']['acct_pwd_policy']['pwd_ttl']/(24*60*60)
        data['data']['acct_pwd_policy']['pwd_ttl'] = max_exp_day

        if request.method == 'POST':
            newpwd = request.POST['newpwd']
            newpwd2 = request.POST['newpwd2']
            user = res_dict['data']['user_id']
            if not newpwd and newpwd2:
                err_msg = '密码不能为空'
                return render(request, 'mustchangepwd.html', {'err_msg': err_msg, 'data': data})
            if newpwd != newpwd2:
                err_msg = "提示:输入的两次新密码不同!"
                return render(request, 'mustchangepwd.html', {'err_msg': err_msg, 'data': data})

            ldapcodes = {'0': '修改密码成功, 请重新登录!',
                         '1001': '管理员账号不能通过此工具修改密码，请联系管理员！',
                         '1002': '此账户不能更改密码，请联系管理员！',
                         '1003': '新密码不符合长度要求！',
                         '1004': '新密码不符合复杂度要求！',
                         '1005': '新密码不能包含用户名！',
                         '1006': '新密码不能包含用户名!'}
            ad = ADhandler()
            res = ad.set_pwd(user, newpwd)
            code = res['code']
            if code == '0':
                username = data['data'].get('user_id')
                request.session['username'] = username
                try:
                    del request.session['res_dict']
                except KeyError as e:
                    logger.error(e)
                    raise e
                return render(request, 'finshed.html')
            err_msg = ldapcodes[code]
            return render(request, 'mustchangepwd.html', {'err_msg': err_msg, 'data': data})
        return render(request, 'mustchangepwd.html', {'data': data})
    return render(request, 'login.html')


@csrf_exempt
def forget_pwd(request):
    if request.method == 'POST':
        username = request.POST['username']
        if not username:
            err_msg = '账号不能为空'
            return render(request, 'forgetpwd.html', {'err_msg': err_msg})

        ad = ADhandler()
        res_auth = ad.get_user_status(username)
        if res_auth is False:
            err_msg = '输入的账号不存在'
            return render(request, 'forgetpwd.html', {'err_msg': err_msg})

        if res_auth['user_id']:
            request.session['user'] = username
            se = SendEmail()
            verify_code = se.verify_code()
            email_to = [res_auth['user_id']+'@eptok.com']
            email_subject = "AD域自助修改密码【验证码邮件】"
            email_content = "验证码: %s" % (verify_code,)
            try:
                se.send_mail(email_to, email_subject, email_content)
            except Exception as e:
                logger.error(e)
                raise e
            request.session['verify_code'] = verify_code
            request.session['res_auth'] = res_auth
            return HttpResponseRedirect('/forgetpass/')

    return render(request, 'forgetpwd.html')


@csrf_exempt
def forget_pass(request):
    username = request.session.get('user', False)
    verify_code = request.session.get('verify_code', False)
    res_auth = request.session.get('res_auth', False)
    print(username)
    print(verify_code)
    print(res_auth)
    if not username or not verify_code or not res_auth:
        return HttpResponseRedirect('/login/')
    print(verify_code)
    print(res_auth)
    if res_auth['acct_pwd_policy']['pwd_complexity_enforced'] == 1:
        res_auth['acct_pwd_policy']['pwd_complexity_enforced'] = '已启用'
    if res_auth['acct_pwd_policy']['pwd_complexity_enforced'] == 0:
        res_auth['acct_pwd_policy']['pwd_complexity_enforced'] = '未启用'
    max_exp_day = res_auth['acct_pwd_policy']['pwd_ttl'] / (24 * 60 * 60)
    res_auth['acct_pwd_policy']['pwd_ttl'] = max_exp_day
    if request.method == 'POST':
        verifycode = request.POST['verifycode']
        newpwd = request.POST['newpwd']
        newpwd2 = request.POST['newpwd2']
        user = res_auth['user_id']
        if not verify_code:
            err_msg = '验证码不能为空!'
            return render(request, 'forgetpass.html', {'err_msg': err_msg, 'data': res_auth})
        if verify_code != verifycode:
            err_msg = '验证码错误!'
            return render(request, 'forgetpass.html', {'err_msg': err_msg, 'data': res_auth})
        if not newpwd or not newpwd2:
            err_msg = '密码不能为空!'
            return render(request, 'forgetpass.html', {'err_msg': err_msg, 'data': res_auth})
        if newpwd != newpwd2:
            err_msg = "提示:输入的两次新密码不同!"
            return render(request, 'forgetpass.html', {'err_msg': err_msg, 'data': res_auth})

        ldapcodes = {'0': '修改密码成功, 请重新登录!',
                     '1001': '管理员账号不能通过此工具修改密码，请联系管理员！',
                     '1002': '此账户不能更改密码，请联系管理员！',
                     '1003': '新密码不符合长度要求！',
                     '1004': '新密码不符合复杂度要求！',
                     '1005': '新密码不能包含用户名！',
                     '1006': '新密码不能包含用户名!'}
        ad = ADhandler()
        res = ad.set_pwd(user, newpwd)
        code = res['code']
        if code == '0':
            username = res_auth.get('user_id')
            request.session['username'] = username
            try:
                del request.session['username']
                del request.session['res_auth']
                del request.session['verify_code']
            except KeyError as e:
                logger.error(e)
                raise e
            return render(request, 'finshed.html')
        err_msg = ldapcodes[code]
        return render(request, 'forgetpass.html', {'err_msg': err_msg, 'data': res_auth})

    return render(request, 'forgetpass.html', {'data': res_auth})


def cancelpwd(request):
    try:
        del request.session['user']
        del request.session['res_auth']
        del request.session['verify_code']
    except KeyError as e:
        logger.error(e)
        raise e
    return render(request, 'login.html')
