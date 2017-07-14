from django import forms
from usermgt.adhandler import ADhandler


class LoginFrom(forms.Form):
    username = forms.CharField(required=True, error_messages={'required': '账户不能为空'})
    password = forms.CharField(required=True, error_messages={'required': '密码不能为空'})

    def clean(self):
        if self.cleaned_data:
            data = dict(self.cleaned_data)
            username = data['username']
            password = data['password']
            try:
                ad = ADhandler()
                msg = ad.user_authn(username, password)
                if msg is not True:
                    code = msg['code']
                    ldapcodes = {'525': '账户不存在！',
                                 '52e': '密码错误！',
                                 '530': '该账户此时间段不允许登录！',
                                 '531': '该账户此工作站不允许登录！',
                                 '532': '密码过期',
                                 '533': '账户被禁用，请联系管理员！',
                                 '701': '账户已过期！',
                                 '773': '下次登录强制修改密码！',
                                 '775': '账户已被锁，请联系管理员！'}
                    self.errors['错误信息：'] = ldapcodes[code]
                    return msg
                data = ad.get_user_status(username)
                return data
            except Exception as e:
                raise e
