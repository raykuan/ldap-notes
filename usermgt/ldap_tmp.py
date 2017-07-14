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
        self.cert_file = '/raykuan/workspace/ldap_rync/certnew.pem'
        self.uri = 'ldaps://%s:636' % (self.host,)
        # self.attr = {}

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
        # search_scope = ldap.SCOPE_SUBTREE
        search_scope = ldap.SCOPE_ONELEVEL

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
            print(results)
