import re
import datetime
import ldap
import logging
import random
log = logging.getLogger('django')


# Python LDAP连接AD服务器初始化需配置的全部参数
BASE_DN = 'dc=test,dc=com'
HOST = random.choice(['192.168.22.101', '192.168.22.102'])
BIND_DN = 'CN=ldap,OU=运维部,OU=测试集团,DC=test,DC=com'
BIND_RDN = 'ldap@test.com'
BIND_PWD = 'P@ssw0rd'
CERT_FILE = './cert/ad_test.pem'
LDAP_URI = 'ldaps://%s:636' % (HOST,)


class ActiveDirectory:
    # 自定义配置当用户账号出现如下几种状态时能否修改密码
    # ['acct_pwd_expired', 'acct_expired', 'acct_disabled', 'acct_locked']
    can_change_pwd_states = ['acct_pwd_expired']
    domain_pwd_policy = {}  # 全局域密码策略
    granular_pwd_policy = {}  # 细颗粒度的DN密码策略keys are policy DNs

    def __init__(self):
        self.conn = None
        self.base_dn = BASE_DN
        self.host = HOST
        self.bind_dn = BIND_DN
        self.bind_rdn = BIND_RDN
        self.bind_pwd = BIND_PWD
        self.cert_file = CERT_FILE
        self.uri = LDAP_URI
        ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)

        try:
            self.conn = ldap.initialize(self.uri)
            self.conn.set_option(ldap.OPT_REFERRALS, 0)
            self.conn.set_option(ldap.OPT_PROTOCOL_VERSION, 3)
            self.conn.set_option(ldap.OPT_X_TLS, ldap.OPT_X_TLS_DEMAND)
            self.conn.set_option(ldap.OPT_X_TLS_DEMAND, True)
            self.conn.set_option(ldap.OPT_DEBUG_LEVEL, 255)
            self.conn.set_option(ldap.OPT_X_TLS_CACERTFILE, self.cert_file)
            self.conn.simple_bind_s(self.bind_rdn, self.bind_pwd)

            if not self.is_admin(self.bind_dn):
                # 如果绑定的用户名不属于管理员组就抛出异常
                raise Exception('绑定的用户必须有管理员权限')
            self.get_pwd_policies()  # 获取全局域密码策略
        except ldap.LDAPError as e:
            raise e

    def is_admin(self, search_dn, admin=0):
        # Recursively look at what groups search_dn is a member of.
        # If we find a search_dn is a member of the builtin Administrators group, return true.

        if not self.conn:
            return None
        try:
            results = self.conn.search_s(search_dn, ldap.SCOPE_BASE, '(memberOf=*)', ['memberOf'])
        except ldap.LDAPError as e:
            raise e
        if not results:
            return 0
        if ('CN=Administrators,CN=Builtin,' + self.base_dn).lower() in [g.decode().lower() for g in results[0][1].get('memberOf', None)]:
            return 1
        group_list = []
        for group in results[0][1]['memberOf']:
            group_list.append(group)
            if group not in group_list:
                admin |= self.is_admin(group.decode())
                # Break early once we detect admin
                if admin:
                    return admin
        return admin

    def get_pwd_policies(self):
        # 获取密码策略方法
        default_policy_container = self.base_dn
        default_policy_attribs = [
            'maxPwdAge',
            'minPwdLength',
            'pwdHistoryLength',
            'pwdProperties',
            'lockoutThreshold',
            'lockOutObservationWindow',
            'lockoutDuration'
        ]

        default_policy_map = {
            'maxPwdAge': 'pwd_ttl',
            'minPwdLength': 'pwd_length_min',
            'pwdHistoryLength': 'pwd_history_depth',
            'pwdProperties': 'pwd_complexity_enforced',
            'lockoutThreshold': 'pwd_lockout_threshold',
            'lockOutObservationWindow': 'pwd_lockout_window',
            'lockoutDuration': 'pwd_lockout_ttl'
        }

        granular_policy_container = 'CN=Password Settings Container,CN=System,%s' % (self.base_dn,)
        granular_policy_filter = '(objectClass=msDS-PasswordSettings)'

        granular_policy_attribs = [
            'msDS-LockoutDuration',
            'msDS-LockoutObservationWindow',
            'msDS-PasswordSettingsPrecedence',
            'msDS-MaximumPasswordAge',
            'msDS-LockoutThreshold',
            'msDS-MinimumPasswordLength',
            'msDS-PasswordComplexityEnabled',
            'msDS-PasswordHistoryLength'
        ]

        granular_policy_map = {
            'msDS-MaximumPasswordAge': 'pwd_ttl',
            'msDS-MinimumPasswordLength': 'pwd_length_min',
            'msDS-PasswordComplexityEnabled': 'pwd_complexity_enforced',
            'msDS-PasswordHistoryLength': 'pwd_history_depth',
            'msDS-LockoutThreshold': 'pwd_lockout_threshold',
            'msDS-LockoutObservationWindow': 'pwd_lockout_window',
            'msDS-LockoutDuration': 'pwd_lockout_ttl',
            'msDS-PasswordSettingsPrecedence': 'pwd_policy_priority'
        }

        if not self.conn:
            return None
        try:
            # AD域范围内的策略.
            results = self.conn.search_s(default_policy_container, ldap.SCOPE_BASE)
        except ldap.LDAPError as e:
            raise e
        dpp = dict([(default_policy_map[k], results[0][1][k][0]) for k in default_policy_map.keys()])
        dpp["pwd_policy_priority"] = 0  # 0表示不用对它计算优先级
        self.domain_pwd_policy = self.sanitize_pwd_policy(dpp)
        # Server 2008r2 only. Per-group policies in CN=Password Settings Container,CN=System
        results = self.conn.search_s(granular_policy_container, ldap.SCOPE_ONELEVEL, granular_policy_filter,
                                     granular_policy_attribs)
        for policy in results:
            gpp = dict([(granular_policy_map[k], policy[1][k][0]) for k in granular_policy_map.keys()])
            self.granular_pwd_policy[policy[0]] = self.sanitize_pwd_policy(gpp)
            self.granular_pwd_policy[policy[0]]['pwd_policy_dn'] = policy[0]

    def sanitize_pwd_policy(self, pwd_policy):
        # 密码策略
        valid_policy_entries = [
            'pwd_ttl',
            'pwd_length_min',
            'pwd_history_depth',
            'pwd_complexity_enforced',
            'pwd_lockout_threshold',
            'pwd_lockout_window',
            'pwd_lockout_ttl',
            'pwd_policy_priority'
        ]

        if len(set(valid_policy_entries) - set(pwd_policy.keys())) != 0:
            return None

        # 密码历史记录次数限制
        pwd_policy['pwd_history_depth'] = int(pwd_policy['pwd_history_depth'])

        # 最短密码长度
        pwd_policy['pwd_length_min'] = int(pwd_policy['pwd_length_min'])

        # 密码复杂度要求
        pwd_policy['pwd_complexity_enforced'] = (
            int(pwd_policy['pwd_complexity_enforced']) & 0x1
            if pwd_policy['pwd_complexity_enforced'] not in ['TRUE', 'FALSE']
            else int({'TRUE': 1, 'FALSE': 0}[pwd_policy['pwd_complexity_enforced']])
        )

        # 密码最长使用多久后会要求用户更改密1970 timestamp 15552000
        pwd_policy['pwd_ttl'] = self.ad_time_to_seconds(pwd_policy['pwd_ttl'])

        # 密码尝试失败次数过多导致帐户锁定后，帐户的锁定时长(单位是秒)
        pwd_policy['pwd_lockout_ttl'] = self.ad_time_to_seconds(pwd_policy['pwd_lockout_ttl'])

        # 密码计数器出现错误后多长时间进行重置(单位是秒)
        pwd_policy['pwd_lockout_window'] = self.ad_time_to_seconds(pwd_policy['pwd_lockout_window'])

        # 锁定用户帐户前允许的密码尝试失败次数(0代表不锁定)
        pwd_policy['pwd_lockout_threshold'] = int(pwd_policy['pwd_lockout_threshold'])

        # 同一用户在使用不同密码策略的多个组中具有成员资格时，建立优先次序
        pwd_policy['pwd_policy_priority'] = int(pwd_policy['pwd_policy_priority'])
        return pwd_policy

    # AD's date format is 100 nanosecond intervals since Jan 1 1601 in GMT.
    # To convert to seconds, divide by 10000000.
    # To convert to UNIX, convert to positive seconds and add 11644473600 to be seconds since Jan 1 1970 (epoch).

    def ad_time_to_seconds(self, ad_time):
        return -(int(ad_time) / 10000000)

    def ad_seconds_to_unix(self, ad_seconds):
        return (int(ad_seconds) + 11644473600) if int(ad_seconds) != 0 else 0

    def ad_time_to_unix(self, ad_time):
        #  A value of 0 or 0x7FFFFFFFFFFFFFFF (9223372036854775807) indicates that the account never expires.
        # FIXME: Better handling of account-expires!
        ad_time = ad_time.decode()
        if ad_time == "9223372036854775807":
            ad_time = "0"
        ad_seconds = self.ad_time_to_seconds(ad_time)
        return -self.ad_seconds_to_unix(ad_seconds)

    def user_authn(self, user, user_pwd):
        # 通过传入的user和user_pwd去绑定ldap查找DN, 成功返回True抛出异常则验证失败
        try:
            status = self.get_user_status(user)
            if status.get('code', None) != '200':
                return status
            status = status['data']
            bind_dn = status['user_dn']
            user_conn = ldap.initialize(self.uri)
            user_conn.simple_bind_s(bind_dn, user_pwd)
        except ldap.INVALID_CREDENTIALS as e:
            raise Exception(self.parse_invalid_credentials(e, bind_dn))
        except ldap.LDAPError as e:
            raise e
        return {'code': '200', 'result': 'success', 'msg': '用户和密码验证成功', 'data': status}

    def get_user_status(self, user, ou=None):
        if ou:
            user_base = "ou=%s,%s" % (ou, self.base_dn)
        else:
            user_base = self.base_dn
        # user_filter = "(sAMAccountName=%s)" % (user,)
        # searchFiltername = 'sAMAccountName'
        searchFilter = '(&(objectClass=person)(sAMAccountName=%s))' % (user,)
        user_scope = ldap.SCOPE_SUBTREE
        status_attribs = [
            'pwdLastSet',
            'accountExpires',
            'userAccountControl',
            'memberOf',
            'msDS-User-Account-Control-Computed',
            'msDS-UserPasswordExpiryTimeComputed',
            'msDS-ResultantPSO',
            'lockoutTime',
            'sAMAccountName',
            'displayName',
            'mail',
            'company',
            'department',
            'title',
            'mobile',
            'l'
        ]

        user_status = {
            'user_dn': '',
            'user_id': '',
            'user_displayname': '',
            'acct_pwd_expiry_enabled': '',
            'acct_pwd_expiry': '',
            'acct_pwd_last_set': '',
            'acct_pwd_expired': '',
            'acct_pwd_policy': '',
            'acct_disabled': '',
            'acct_locked': '',
            'acct_locked_expiry': '',
            'acct_expired': '',
            'acct_expiry': '',
            'acct_can_change_pwd': '',
            'acct_bad_states': [],
            'mail': '',
            'company': '',
            'department': '',
            'title': '',
            'mobile': '',
            'region': ''
        }

        bad_states = ['acct_locked', 'acct_disabled', 'acct_expired', 'acct_pwd_expired']

        try:
            # 查询status_attribs列表中指定的用户信息
            results_tmp = self.conn.search_s(user_base, user_scope, searchFilter, status_attribs)
            results = []
        except ldap.LDAPError as e:
            raise e

        if len(results_tmp) != 1:
            for s in range(len(results_tmp)):
                if results_tmp[s][0]:
                    results.append(results_tmp[s])
        else:
            results = results_tmp[0][0]
        if len(results) != 1:  # sAMAccountName must be unique
            return {'code': '525', 'result': 'failed', 'msg': '账户不存在'}

        result = results[0]
        user_dn = result[0]
        user_attribs = result[1]

        # UserAccountControl用于属性表示帐户的行为和特征，具体参见微软官方对照表
        uac = int(user_attribs.get('userAccountControl', None)[0])

        # msDS-User-Account-Control-Computed属性也表示详细的帐户特征
        uac_live = int(user_attribs.get('msDS-User-Account-Control-Computed', None)[0])

        s = user_status
        s['user_dn'] = user_dn
        s['user_id'] = user_attribs.get('sAMAccountName', None)[0].decode()
        s['user_displayname'] = user_attribs.get('displayName', None)[0].decode()

        if user_attribs.get('mail', None):
            s['mail'] = user_attribs.get('mail', None)[0].decode()

        if user_attribs.get('company', None):
            s['company'] = user_attribs.get('company', None)[0].decode()

        if user_attribs.get('department', None):
            s['department'] = user_attribs.get('department', None)[0].decode()

        if user_attribs.get('title', None):
            s['title'] = user_attribs.get('title', None)[0].decode()

        if user_attribs.get('mobile', None):
            s['mobile'] = user_attribs.get('mobile', None)[0].decode()

        if user_attribs.get('l', None):
            s['region'] = user_attribs.get('l', None)[0].decode()

        # AD密码复杂度要求不能超过2个单词在displayName列表中
        s['user_displayname_tokenized'] = [a for a in re.split('[,.\-_ #\t]+', (s['user_displayname'])) if len(a) > 2]

        # uac_live(msDS-User-Account-Control-Computed)中包含了账号被锁、账号被禁用状态
        s['acct_locked'] = (1 if (uac_live & 0x00000010) else 0)
        s['acct_disabled'] = (1 if (uac & 0x00000002) else 0)

        # 账号过期的时间戳
        s['acct_expiry'] = self.ad_time_to_unix(user_attribs.get('accountExpires', None)[0])

        # 账号是否过期0代表不过期1代表过期(此语句须保证在Linux系统才能正确运行，window因时间取值格式不兼容会抛出OSError)
        s['acct_expired'] = (0 if datetime.datetime.fromtimestamp(s['acct_expiry']) > datetime.datetime.now() or s['acct_expiry'] == 0 else 1)

        # 最后一次修改密码的时间戳
        s['acct_pwd_last_set'] = self.ad_time_to_unix(user_attribs.get('pwdLastSet', None)[0])

        # 帐户的密码是否设置永不过期(1代表永不过期)
        s['acct_pwd_expiry_enabled'] = (0 if (uac & 0x00010000) else 1)

        # 对于密码过期，需要确定哪些策略（如果有的话）适用于该用户
        # msDS-ResultantPSO(对于Server 2008+之后的版本如果应用了PSO多元密码策略将会提交此属性)
        # 如果没有提交msDS-ResultantPSO属性，就用默认的域策略
        if 'msDS-ResultantPSO' in user_attribs and user_attribs.get('msDS-ResultantPSO', None)[0] in self.granular_pwd_policy:
            s['acct_pwd_policy'] = self.granular_pwd_policy[user_attribs.get('msDS-ResultantPSO', None)[0]]
        else:
            s['acct_pwd_policy'] = self.domain_pwd_policy

        # If account is locked, expiry comes from lockoutTime + policy lockout ttl.
        # lockoutTime is only reset to 0 on next successful login.
        s['acct_locked_expiry'] = (self.ad_time_to_unix(user_attribs.get('lockoutTime', None)[0]) + s['acct_pwd_policy']['pwd_lockout_ttl'] if s['acct_locked'] else 0)

        # msDS-UserPasswordExpiryTimeComputed表示账号什么时间将会过期，如果从不过期这个值会很大
        s['acct_pwd_expiry'] = self.ad_time_to_unix(user_attribs['msDS-UserPasswordExpiryTimeComputed'][0])

        # 表示账号是否过期(0代表未过期, 1代表过期)
        s['acct_pwd_expired'] = (1 if (uac_live & 0x00800000) else 0)

        for state in bad_states:
            if s[state]:
                s['acct_bad_states'].append(state)

        # 如果s['acct_bad_states']存在,但self.can_change_pwd_states不存在,则该用户不能修改密码
        s['acct_can_change_pwd'] = (0 if (len(set(s['acct_bad_states']) - set(self.can_change_pwd_states)) != 0) else 1)
        # return s
        return {'code': '200', 'result': 'success', 'msg': '成功获取用户信息', 'data': s}

    def change_pwd(self, user, current_pwd, new_pwd):
        # 通过旧密码修改账户密码
        # 密码需满足/长度/复杂度/历史记录/三个要求
        # 必须存在用户, not be priv'd, 状态必须在自定义的self.can_change_pwd_states列表中
        status = self.get_user_status(user)
        if status.get('code', None) != '200':
            return status
        status = status['data']
        user_dn = status['user_dn']

        # 限制管理员远程修改密码
        # if self.is_admin(user_dn):
        #     return {'code': '5551', 'result': 'failed', 'msg': '%s 是管理员账号不能用此工具修改密码' % (user,)}

        # 判断全局配置中是否有不能修改密码项
        if not status['acct_can_change_pwd']:
            # raise self.user_cannot_change_pwd(user, status, self.can_change_pwd_states)
            return {'code': '5553', 'result': 'failed', 'msg': '%s 不能修改密码: %s' % (user, ', '.join((set(status['acct_bad_states']) - set(self.can_change_pwd_states))))}

        # 新密码必须遵循域策略
        if len(new_pwd) < status['acct_pwd_policy']['pwd_length_min']:
            msg = '新密码最少%d位长度本次只提交了%d位' % (status['acct_pwd_policy']['pwd_length_min'], len(new_pwd))
            return {'code': '5552', 'result': 'failed', 'msg': '%s %s' % (user, msg)}

        # 新密码复杂度检查username/displayname需满足四项中的最少三项
        if status['acct_pwd_policy']['pwd_complexity_enforced']:
            patterns = [
                r'.*(?P<digit>[0-9]).*',
                r'.*(?P<lowercase>[a-z]).*',
                r'.*(?P<uppercase>[A-Z]).*',
                r'.*(?P<special>[~!@#$%^&*_\-+=`|\\(){}\[\]:;"\'<>,.?/]).*'
            ]
            matches = []
            for pattern in patterns:
                match = re.match(pattern, new_pwd)
                if match and match.groupdict() and match.groupdict().keys():
                    matches.append(list(match.groupdict().keys()))
            if len(matches) < 3:
                msg = '新密码必须包含(大、小写、数字、特殊字符)其中三种, 当前只符合%d种.' % (len(matches),)
                return {'code': '5552', 'result': 'failed', 'msg': '%s %s' % (user, msg)}

            # 密码不能包含用户名
            if status['user_id'].lower() in new_pwd.lower():
                msg = '密码不能包含用户名'
                return {'code': '5552', 'result': 'failed', 'msg': '%s %s' % (user, msg)}

            # 密码不能包含displayname
            for e in status['user_displayname_tokenized']:
                if len(e) > 2 and e.lower() in new_pwd.lower():
                    msg = '密码不能包含在(%s)中两个以上的字符, 但是发现有: %s.' % (', '.join(status['user_displayname_tokenized']), e)
                    return {'code': '5552', 'result': 'failed', 'msg': '%s %s' % (user, msg)}

        # Encode密码并且修改，如果服务器未通过, 历史记录错误会增加.
        current_pwd = ('\"' + current_pwd + '\"').encode('utf-16-le')
        new_pwd = ('\"' + new_pwd + '\"').encode('utf-16-le')
        pass_mod = [(ldap.MOD_DELETE, 'unicodePwd', [current_pwd]), (ldap.MOD_ADD, 'unicodePwd', [new_pwd])]

        try:
            self.conn.modify_s(user_dn, pass_mod)
        except ldap.CONSTRAINT_VIOLATION as e:
            # If the exceptions's 'info' field begins with:
            # 00000056 - 旧密码不匹配
            # 0000052D - 新密码不符合复杂度要求
            e = eval(str(e))
            msg = e['desc']
            if e['info'].startswith('00000056'):
                return {'code': '52e', 'result': 'failed', 'msg': '旧密码验证失败'}
            elif e['info'].startswith('0000052D'):
                msg = '新密码不能和最近%d次使用过的相同.' % (status['acct_pwd_policy']['pwd_history_depth'],)
            return {'code': '5552', 'result': 'failed', 'msg': '%s 新密码不符合要求: %s' % (user, msg)}
        except ldap.LDAPError as e:
            raise e

        return {'code': '200', 'result': 'success', 'msg': '修改密码成功', 'data': ''}

    def set_pwd(self, user, new_pwd):
        # 重置密码，只需提供新密码不验证旧密码，用户必须存在
        status = self.get_user_status(user)
        if status.get('code', None) != '200':
            return status
        status = status['data']
        user_dn = status['user_dn']

        # 限制管理员远程修改密码
        # if self.is_admin(user_dn):
        #     return {'code': '5551', 'result': 'failed', 'msg': '%s 是管理员账号不能用此工具修改密码' % (user,)}

        # 新密码必须符合密码策略最小长度
        if len(new_pwd) < status['acct_pwd_policy']['pwd_length_min']:
            msg = '新密码最少%d位长度本次只提交了%d位' % (status['acct_pwd_policy']['pwd_length_min'], len(new_pwd))
            return {'code': '5552', 'result': 'failed', 'msg': '%s 新密码不符合要求: %s' % (user, msg)}

        # 判断全局配置中是否有不能修改密码项
        if not status['acct_can_change_pwd']:
            # raise self.user_cannot_change_pwd(user, status, self.can_change_pwd_states)
            return {'code': '5553', 'result': 'failed', 'msg': '%s 不能修改密码: %s' % (user, ', '.join((set(status['acct_bad_states']) - set(self.can_change_pwd_states))))}

        # 新密码复杂度检查username/displayname需满足四项中的最少三项
        if status['acct_pwd_policy']['pwd_complexity_enforced']:
            patterns = [
                r'.*(?P<digit>[0-9]).*',
                r'.*(?P<lowercase>[a-z]).*',
                r'.*(?P<uppercase>[A-Z]).*',
                r'.*(?P<special>[~!@#$%^&*_\-+=`|\\(){}\[\]:;"\'<>,.?/]).*'
            ]
            matches = []
            for pattern in patterns:
                match = re.match(pattern, new_pwd)
                if match and match.groupdict() and match.groupdict().keys():
                    matches.append(list(match.groupdict().keys()))
            if len(matches) < 3:
                msg = '新密码必须包含(大、小写、数字、特殊字符)其中三种, 当前只符合%d种.' % (len(matches),)
                return {'code': '5552', 'result': 'failed', 'msg': '%s %s' % (user, msg)}

            # 密码不能包含用户名
            if status['user_id'].lower() in new_pwd.lower():
                return {'code': '5552', 'result': 'failed', 'msg': '%s 新密码不能包含用户名' % (user,)}

            # 密码不能包含displayname
            for e in status['user_displayname_tokenized']:
                if len(e) > 2 and e.lower() in new_pwd.lower():
                    msg = '密码不能包含在(%s)中两个以上的字符, 但是发现有: %s.' % (', '.join(status['user_displayname_tokenized']), e)
                    return {'code': '5552', 'result': 'failed', 'msg': '%s %s' % (user, msg)}

        # new_pwd = ('\"' + new_pwd + '\"', "iso-8859-1").encode('utf-16-le')
        new_pwd = ('\"' + new_pwd + '\"').encode('utf-16-le')
        pass_mod = [(ldap.MOD_REPLACE, 'unicodePwd', [new_pwd])]
        try:
            self.conn.modify_s(user_dn, pass_mod)
        except ldap.LDAPError as e:
            raise e

        return {'code': '200', 'result': 'success', 'msg': '重置密码成功', 'data': ''}

    def force_change_pwd(self, user):
        # 将密码过期的用户状态强制修改为正常状态
        # 不验证旧密码，用户必须存在
        status = self.get_user_status(user)
        if status.get('code', None) != '200':
            return status
        status = status['data']
        user_dn = status['user_dn']

        # 限制管理员远程修改密码
        # if self.is_admin(user_dn):
        #     return {'code': '5551', 'result': 'failed', 'msg': '%s 是管理员账号不能用此工具修改密码' % (user,)}

        if status['acct_pwd_expiry_enabled']:
            mod = [(ldap.MOD_REPLACE, 'pwdLastSet', [0])]
            try:
                self.conn.modify_s(user_dn, mod)
            except ldap.LDAPError as e:
                raise e
        return {'code': '200', 'result': 'success', 'msg': '修改密码状态成功', 'data': ''}

    def parse_invalid_credentials(self, e, user_dn):
        if not isinstance(e, ldap.INVALID_CREDENTIALS):
            return None
        ldapcodes = {
            '525': '账号不存在',
            '52e': '账号密码错误',
            '530': '该账号登录受限, 一段时间内不允许登录',
            '531': '该账号登录受限, 在此workstation不允许登录',
            '532': '该账号密码已过期',
            '533': '该账号被禁用',
            '701': '该账号已过期',
            '773': '该账户本次登录需强制修改密码',
            '775': '该账户被锁定'
        }

        ldapcode_pattern = r".*AcceptSecurityContext error, data (?P<ldapcode>[^,]+),"
        e = eval(str(e))
        # m = re.match(ldapcode_pattern, e[0]['info'])
        m = re.match(ldapcode_pattern, e['info'])
        result = {}

        if not m or not len(m.groups()) > 0 or m.group('ldapcode') not in ldapcodes:
            result['code'] = '52e'
            result['result'] = 'failed'
            result['msg'] = '%s 账号密码验证失败' % (user_dn,)
            return result

        code = m.group('ldapcode')

        if code == '525':
            result['code'] = '525'
            result['result'] = 'failed'
            result['msg'] = '%s 账号不存在' % (user_dn,)
            return result

        if code == '52e':
            result['code'] = '52e'
            result['result'] = 'failed'
            result['msg'] = '%s 账号密码验证失败' % (user_dn,)
            return result

        if code == '530':
            result['code'] = '530'
            result['result'] = 'failed'
            result['msg'] = '%s 该账号此时段被限制登录' % (user_dn,)
            return result

        if code == '531':
            result['code'] = '531'
            result['result'] = 'failed'
            result['errmsg'] = '%s 账号在此workstation被限制登录' % (user_dn,)
            return result

        if code == '532':
            result['code'] = '532'
            result['result'] = 'failed'
            result['msg'] = '%s 该账号密码已过期' % (user_dn,)
            return result

        if code == '533':
            result['code'] = '533'
            result['result'] = 'failed'
            result['msg'] = '%s 该账号被禁用' % (user_dn,)
            return result

        if code == '701':
            result['code'] = '701'
            result['result'] = 'failed'
            result['msg'] = '%s 该账号已过期' % (user_dn,)
            return result

        if code == '773':
            result['code'] = '773'
            result['result'] = 'failed'
            result['msg'] = '%s 该账号密码被管理员设置为过期(下次登录需强制修改密码)' % (user_dn,)
            return result

        if code == '775':
            result['code'] = '775'
            result['result'] = 'failed'
            result['msg'] = '%s 密码错误次数过多账户被锁，需联系管理员解锁' % (user_dn,)
            return result


if __name__ == '__main__':
    # pass
    a = ActiveDirectory()
    str1 = 'CN=张三,OU=研发,OU=测试集团,DC=test,DC=com'
    str2 = 'CN=ldap,OU=运维,OU=测试集团,DC=test,DC=com'
    str3 = 'CN=yf zuzhang,OU=研发,OU=测试集团,DC=test,DC=com'
    str4 = 'CN=yw os,OU=运维,OU=测试集团,DC=test,DC=com'
    # res = a.is_admin(str2)
    # res = a.get_user_status('rayk')
    res = a.user_authn('rayk', 'Ray#8023')
    # res = a.change_pwd('rayk', 'Ray#8023', 'rayk@111')
    # res = a.user_authn_pwd_verify('rayk', 'rayk@111')
    import pprint
    pprint.pprint(res)
