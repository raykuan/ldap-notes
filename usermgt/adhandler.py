import ldap
import datetime
import re


class ADhandler(object):
    can_change_pwd_states = ['acct_pwd_expired']
    domain_pwd_policy = {}
    granular_pwd_policy = {}  # keys are policy DNs

    def __init__(self):
        ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
        self.conn = None
        self.basedn = "dc=raykuan,dc=com"
        self.host = '192.168.7.111'
        self.binddn = 'ldap@raykuan.com'
        self.bindpwd = 'Abc123!@#'
        self.cert_file = '/raykuan/workspace/ldap_rync/scertnew.pem'
        self.uri = 'ldaps://%s:636' % (self.host,)
        self.result = {
            'code': '',
            'code_info': '',
            'data': '',
        }

        try:
            self.conn = ldap.initialize(self.uri)
            self.conn.set_option(ldap.OPT_REFERRALS, 0)
            self.conn.set_option(ldap.OPT_PROTOCOL_VERSION, 3)
            self.conn.set_option(ldap.OPT_X_TLS, ldap.OPT_X_TLS_DEMAND)
            self.conn.set_option(ldap.OPT_X_TLS_DEMAND, True)
            self.conn.set_option(ldap.OPT_DEBUG_LEVEL, 255)
            self.conn.set_option(ldap.OPT_X_TLS_CACERTFILE, self.cert_file)
            s = self.conn.simple_bind_s(self.binddn, self.bindpwd)
            print(s)
            # if not self.is_admin(self.binddn):
            self.get_pwd_policies()
        except ldap.LDAPError as e:
            raise e

    def get_user_status(self, user, ou=None):
        if ou:
            user_basedn = "ou=%s,%s" % (ou, self.basedn)
        else:
            user_basedn = self.basedn

        # user_filter = '(sAMAccountName=%s)' % (user,)
        # search_filtername = 'sAMAccountName'
        search_filter = '(&(objectClass=person)(sAMAccountName=%s))' % (user,)
        search_scope = ldap.SCOPE_SUBTREE

        retrieve_attributes = [
            'pwdLastSet',
            'accountExpires',
            'userAccountControl',
            'memberOf',
            'msDS-User-Account-Control-Computed',
            'msDS-UserPasswordExpiryTimeComputed',
            'msDS-ResultantPSO',
            'lockoutTime',
            'sAMAccountName',
            'displayName'
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
            'acct_bad_states': []
        }

        bad_states = ['acct_locked', 'acct_disabled', 'acct_expired', 'acct_pwd_expired']

        try:
            # search for user
            results_tmp = self.conn.search_s(user_basedn, search_scope, search_filter, retrieve_attributes)
            results = []
            print(results_tmp)
        except ldap.LDAPError as e:
            raise e

        if len(results_tmp) != 1:
            for s in range(len(results_tmp)):
                if results_tmp[s][0]:
                    results.append(results_tmp[s])
            print(results)
        else:
            results = results_tmp[0][0]
        if len(results) != 1:  # sAMAccountName must be unique
            return False

        result = results[0]
        user_dn = result[0]
        user_attribs = result[1]
        uac = int(user_attribs['userAccountControl'][0])
        uac_live = int(user_attribs['msDS-User-Account-Control-Computed'][0])
        s = user_status
        s['user_dn'] = user_dn
        s['user_id'] = user_attribs['sAMAccountName'][0].decode()
        s['user_displayname'] = user_attribs['displayName'][0].decode()
        # AD complexity will not allow a word longer than 2 characters as part of displayName
        s['user_displayname_tokenized'] = [a for a in re.split('[,.\-_ #\t]+', (s['user_displayname'])) if len(a) > 2]
        # uac_live (msDS-User-Account-Control-Computed) contains current locked, pwd_expired status
        s['acct_locked'] = (1 if (uac_live & 0x00000010) else 0)
        s['acct_disabled'] = (1 if (uac & 0x00000002) else 0)
        s['acct_expiry'] = self.ad_time_to_unix(user_attribs['accountExpires'][0])
        s['acct_expired'] = (0 if datetime.datetime.fromtimestamp(s['acct_expiry']) > datetime.datetime.now() or s['acct_expiry'] == 0 else 1)
        s['acct_pwd_last_set'] = self.ad_time_to_unix(user_attribs['pwdLastSet'][0])
        s['acct_pwd_expiry_enabled'] = (0 if (uac & 0x00010000) else 1)

        # For password expiration need to determine which policy, if any, applies to this user.
        # msDS-ResultantPSO will be present in Server 2008+ and if the user has a PSO applied.
        # If not present, use the domain default.
        if 'msDS-ResultantPSO' in user_attribs and user_attribs['msDS-ResultantPSO'][0] in self.granular_pwd_policy:
            s['acct_pwd_policy'] = self.granular_pwd_policy[user_attribs['msDS-ResultantPSO'][0]]
        else:
            s['acct_pwd_policy'] = self.domain_pwd_policy

        # If account is locked, expiry comes from lockoutTime + policy lockout ttl.
        # lockoutTime is only reset to 0 on next successful login.
        s['acct_locked_expiry'] = (self.ad_time_to_unix(user_attribs['lockoutTime'][0]) +
                                   int(s['acct_pwd_policy']['pwd_lockout_ttl']) if s['acct_locked'] else 0)
        # msDS-UserPasswordExpiryTimeComputed is when a password expires. If never it is very high.
        s['acct_pwd_expiry'] = self.ad_time_to_unix(user_attribs['msDS-UserPasswordExpiryTimeComputed'][0])
        s['acct_pwd_expired'] = (1 if (uac_live & 0x00800000) else 0)
        for state in bad_states:
            if s[state]:
                s['acct_bad_states'].append(state)
        # If there is something in s['acct_bad_states'] not in self.can_change_pwd_states, they can't change pwd.
        s['acct_can_change_pwd'] = (0 if (len(set(s['acct_bad_states']) - set(self.can_change_pwd_states)) != 0) else 1)
        print(s)
        return s

    # def user_authn_pwd_verify(self, user, user_pwd):
    #     # Attempt to bind but only throw an exception if the password is incorrect or the account
    #     # is in a state that would preclude changing the password.
    #     try:
    #         self.user_authn(user, user_pwd)
    #     # except (self.authn_failure_time, self.authn_failure_workstation,
    #     #         (self.authn_failure_pwd_expired_natural if 'acct_pwd_expired' in self.can_change_pwd_states else None),
    #     #         (self.authn_failure_pwd_expired_admin if 'acct_pwd_expired' in self.can_change_pwd_states else None),
    #     #         (self.authn_failure_acct_disabled if 'acct_disabled' in self.can_change_pwd_states else None),
    #     #         (self.authn_failure_acct_expired if 'acct_expired' in self.can_change_pwd_states else None),
    #     #         (self.authn_failure_acct_locked if 'acct_locked' in self.can_change_pwd_states else None)) as e:
    #     except (self.authn_failure_time,
    #             self.authn_failure_workstation,
    #             self.authn_failure_pwd_expired_natural,
    #             self.authn_failure_pwd_expired_admin,
    #             self.authn_failure_acct_disabled,
    #             self.authn_failure_acct_expired,
    #             self.authn_failure_acct_locked) as e:
    #         return True
    #     except ldap.LDAPError:
    #         return False
    #     return True

    def user_authn(self, user, user_pwd):
        # Look up DN for user, bind using current_pwd.
        # Return true on success, exception on failure.
        try:
            status = self.get_user_status(user)
            if status is False:
                self.result['code'] = '525'
                self.result['code_info'] = 'Could not find user %s.' % (user,)
                return self.result
            self.result['data'] = status
            bind_dn = status['user_dn']
            user_dn = status['user_id']
            user_conn = ldap.initialize(self.uri)
            user_conn.simple_bind_s(bind_dn, user_pwd)
        except ldap.INVALID_CREDENTIALS as e:
            result = self.parse_invalid_credentials(e, user_dn)
            return result
        except ldap.LDAPError as e:
            raise e
        self.result['code'] = '0'
        self.result['code_info'] = 'user %s authentication success' % (user,)
        self.result['data'] = status
        return self.result

    def parse_invalid_credentials(self, e, user_dn):
        if not isinstance(e, ldap.INVALID_CREDENTIALS):
            return None
        ldapcodes = {'525': 'user not found',
                     '52e': 'invalid credentials',
                     '530': 'user not permitted to logon at this time',
                     '531': 'user not permitted to logon at this workstation',
                     '532': 'password expired',
                     '533': 'account disabled',
                     '701': 'account expired',
                     '773': 'forced expired password',
                     '775': 'account locked'}
        ldapcode_pattern = r".*AcceptSecurityContext error, data (?P<ldapcode>[^,]+),"
        e = eval(str(e))
        m = re.match(ldapcode_pattern, e['info'])
        if not m or not len(m.groups()) > 0 or m.group('ldapcode') not in ldapcodes:
            ret = {'code': '52e', 'info': e}
            return ret
        code = m.group('ldapcode')
        print(code)
        if code == '525':
            self.result['code'] = '525'
            self.result['code_info'] = 'Could not find user %s.' % (user_dn,)
            return self.result
        if code == '52e':
            self.result['code'] = '52e'
            self.result['code_info'] = 'user "%s" incorrect current password or generic authn failure' % (user_dn,)
            return self.result
        if code == '530':
            self.result['code'] = '530'
            self.result['code_info'] = 'user "%s" user_dn has time of day login restrictions ' \
                                       'and cannot login at this time' % (user_dn,)
            return self.result
        if code == '531':
            self.result['code'] = '531'
            self.result['code_info'] = 'user "%s" user_dn has workstation login restrictions ' \
                                       'and cannot login at this workstation' % (user_dn,)
            return self.result
        if code == '532':
            self.result['code'] = '532'
            self.result['code_info'] = 'user "%s" password has expired naturally' % (user_dn,)
            return self.result
        if code == '533':
            self.result['code'] = '533'
            self.result['code_info'] = 'user "%s" user_dn account disabled' % (user_dn,)
            return self.result
        if code == '701':
            self.result['code'] = '701'
            self.result['code_info'] = 'user "%s" user_dn account expired' % (user_dn,)
            return self.result
        if code == '773':
            self.result['code'] = '773'
            self.result['code_info'] = 'user "%s" password has been administratively expired ' \
                                       '(force change on next login)' % (user_dn,)
            return self.result
        if code == '775':
            self.result['code'] = '775'
            self.result['code_info'] = 'user "%s" account locked due to excessive authentication failures' % (user_dn,)
            return self.result
        return True

    def set_pwd(self, user, new_pwd):
        status = self.get_user_status(user)
        user_dn = status['user_dn']

        if self.is_admin(user_dn):
            self.result['code'] = '1001'
            self.result['code_info'] = '%s is a protected user, their password cannot be changed using this tool.' % (user,)
            return self.result

        if not status['acct_can_change_pwd']:
            msg_tmp = '%s cannot change password for the following reasons: %s' % (
                user, ', '.join((set(status['acct_bad_states']) - set(self.can_change_pwd_states))))
            msg = msg_tmp.rstrip() + '.'
            self.result['code'] = '1002'
            self.result['code_info'] = msg
            return self.result

        if not len(new_pwd) >= int(status['acct_pwd_policy']['pwd_length_min']):
            msg = 'New password for %s must be at least %d characters, submitted password has only %d.'\
                  % (user, int(status['acct_pwd_policy']['pwd_length_min']), len(new_pwd))
            self.result['code'] = '1003'
            self.result['code_info'] = msg
            return self.result

        # Check Complexity - 3of4 and username/displayname check
        if status['acct_pwd_policy']['pwd_complexity_enforced']:
            patterns = [r'.*(?P<digit>[0-9]).*',
                        r'.*(?P<lowercase>[a-z]).*',
                        r'.*(?P<uppercase>[A-Z]).*',
                        r'.*(?P<special>[~!@#$%^&*_\-+=`|\\(){}\[\]:;"\'<>,.?/]).*']
            matches = []
            for pattern in patterns:
                match = re.match(pattern, new_pwd)
                if match and match.groupdict() and match.groupdict().keys():
                    matches.append(list(match.groupdict().keys()))
            if len(matches) < 3:
                msg = 'New password for %s must contain 3 of 4 character types (lowercase, uppercase, digit, special), ' \
                      'only found %s.' % (user, matches)
                self.result['code'] = '1004'
                self.result['code_info'] = msg
                return self.result

        # The new password must not contain user's username
        if status['user_id'].lower() in new_pwd.lower():
            msg = 'New password for %s must not contain their username.' % (user,)
            self.result['code'] = '1005'
            self.result['code_info'] = msg
            return self.result

        # The new password must not contain word from displayname
        for e in status['user_displayname_tokenized']:
            if len(e) > 2 and e.lower() in new_pwd.lower():
                msg = 'New password for %s must not contain a word longer than 2 characters ' \
                      'from your name in our system (%s).' % (user, status['user_displayname_tokenized'])
                self.result['code'] = '1006'
                self.result['code_info'] = msg
                return self.result

        new_pwd = ("\"" + new_pwd + "\"").encode('utf-16-le')
        pass_mod = [(ldap.MOD_REPLACE, 'unicodePwd', [new_pwd])]
        try:
            self.conn.modify_s(user_dn, pass_mod)
        except ldap.LDAPError as e:
            return e
        self.result['code'] = '0'
        self.result['code_info'] = 'set new password success'
        return self.result

    def get_pwd_policies(self):
        default_policy_container = self.basedn
        default_policy_attribs = ['maxPwdAge', 'minPwdLength', 'pwdHistoryLength', 'pwdProperties', 'lockoutThreshold',
                                  'lockOutObservationWindow', 'lockoutDuration']
        default_policy_map = {'maxPwdAge': 'pwd_ttl', 'minPwdLength': 'pwd_length_min',
                              'pwdHistoryLength': 'pwd_history_depth', 'pwdProperties': 'pwd_complexity_enforced',
                              'lockoutThreshold': 'pwd_lockout_threshold',
                              'lockOutObservationWindow': 'pwd_lockout_window', 'lockoutDuration': 'pwd_lockout_ttl'}
        granular_policy_container = 'CN=Password Settings Container,CN=System,%s' % (self.basedn,)
        granular_policy_filter = '(objectClass=msDS-PasswordSettings)'
        granular_policy_attribs = ['msDS-LockoutDuration', 'msDS-LockoutObservationWindow',
                                   'msDS-PasswordSettingsPrecedence', 'msDS-MaximumPasswordAge',
                                   'msDS-LockoutThreshold', 'msDS-MinimumPasswordLength',
                                   'msDS-PasswordComplexityEnabled', 'msDS-PasswordHistoryLength']
        granular_policy_map = {'msDS-MaximumPasswordAge': 'pwd_ttl', 'msDS-MinimumPasswordLength': 'pwd_length_min',
                               'msDS-PasswordComplexityEnabled': 'pwd_complexity_enforced',
                               'msDS-PasswordHistoryLength': 'pwd_history_depth',
                               'msDS-LockoutThreshold': 'pwd_lockout_threshold',
                               'msDS-LockoutObservationWindow': 'pwd_lockout_window',
                               'msDS-LockoutDuration': 'pwd_lockout_ttl',
                               'msDS-PasswordSettingsPrecedence': 'pwd_policy_priority'}
        if not self.conn:
            return None
        try:
            # Load domain-wide policy.
            results = self.conn.search_s(default_policy_container, ldap.SCOPE_BASE)
        except ldap.LDAPError as e:
            raise e
        dpp = dict([(default_policy_map[k], results[0][1][k][0]) for k in default_policy_map.keys()])
        dpp["pwd_policy_priority"] = 0  # 0 Indicates don't use it in priority calculations
        self.domain_pwd_policy = self.sanitize_pwd_policy(dpp)
        # Server 2008r2 only. Per-group policies in CN=Password Settings Container,CN=System
        results = self.conn.search_s(granular_policy_container, ldap.SCOPE_ONELEVEL, granular_policy_filter,
                                     granular_policy_attribs)
        for policy in results:
            gpp = dict([(granular_policy_map[k], policy[1][k][0]) for k in granular_policy_map.keys()])
            self.granular_pwd_policy[policy[0]] = self.sanitize_pwd_policy(gpp)
            self.granular_pwd_policy[policy[0]]['pwd_policy_dn'] = policy[0]

    def sanitize_pwd_policy(self, pwd_policy):
        valid_policy_entries = ['pwd_ttl', 'pwd_length_min', 'pwd_history_depth', 'pwd_complexity_enforced',
                                'pwd_lockout_threshold', 'pwd_lockout_window', 'pwd_lockout_ttl', 'pwd_policy_priority']
        if len(set(valid_policy_entries) - set(pwd_policy.keys())) != 0:
            return None
        pwd_policy['pwd_history_depth'] = int(pwd_policy['pwd_history_depth'])
        pwd_policy['pwd_length_min'] = int(pwd_policy['pwd_length_min'])
        pwd_policy['pwd_complexity_enforced'] = (
            int(pwd_policy['pwd_complexity_enforced']) & 0x1 if pwd_policy['pwd_complexity_enforced'] not in ['TRUE',
                                                                                                              'FALSE'] else int(
                {'TRUE': 1, 'FALSE': 0}[pwd_policy['pwd_complexity_enforced']]))
        pwd_policy['pwd_ttl'] = self.ad_time_to_seconds(pwd_policy['pwd_ttl'])
        pwd_policy['pwd_lockout_ttl'] = self.ad_time_to_seconds(pwd_policy['pwd_lockout_ttl'])
        pwd_policy['pwd_lockout_window'] = self.ad_time_to_seconds(pwd_policy['pwd_lockout_window'])
        pwd_policy['pwd_lockout_threshold'] = int(pwd_policy['pwd_lockout_threshold'])
        pwd_policy['pwd_policy_priority'] = int(pwd_policy['pwd_policy_priority'])
        return pwd_policy

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

    def is_admin(self, search_dn, admin=0):
        # Recursively look at what groups search_dn is a member of.
        # If we find a search_dn is a member of the builtin Administrators group, return true.
        if not self.conn:
            return None
        try:
            results = self.conn.search_s(search_dn, ldap.SCOPE_BASE, '(memberOf=*)', ['memberOf'])
            # print(results[0][1]['memberOf'])
        except ldap.LDAPError as e:
            raise e
        if not results:
            return 0
        if ('CN=Administrators,CN=Builtin,' + self.basedn).lower() in \
                [g.decode().lower() for g in results[0][1]['memberOf']]:
            return 1
        for group in results[0][1]['memberOf']:
            admin |= self.is_admin(group.decode())
            # Break early once we detect admin
            if admin:
                return admin
        return admin


if __name__ == '__main__':
    pass
    # ADhandler().get_user_status('leikuan')
    # ADhandler().get_user_status('leitest')
    # r = ADhandler().set_pwd('leitest', 'Z@aa123')
    # r = ADhandler().user_authn('leitest', 'Abc123!@#')
    # print(r)
    # ADhandler().user_authn_pwd_verify('dulei', 'Abc123!@#')
    # a = ADhandler()
    # res = a.user_authn_pwd_verify('leitest', 'Abc123!@#')
    # print(res)
