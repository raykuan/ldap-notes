# source: http://stackoverflow.com/questions/25299971/python-ldap-converting-objectguid-to-hex-string-and-back

def guid2hexstring(val):
    s = ['\\%02X' % ord(x) for x in val]
    return ''.join(s)

guid = ldapobject.get('objectGUID', [''])[0] # 'Igr\xafb\x19ME\xb2P9c\xfb\xa0\xe2w'
guid2string(guid).replace("\\", "") # '496772AF62194D45B2503963FBA0E277'

#and back to a value you can use in an ldap search filter

guid = ''.join(['\\%s' % guid[i:i+2] for i in range(0, len(guid), 2)]) # '\\49\\67\\72\\AF\\62\\19\\4D\\45\\B2\\50\\39\\63\\FB\\A0\\E2\\77'

searchfilter = ('(objectGUID=%s)' % guid)

# alternatively,
# this works to convert to LDAP Browser-compatible GUID
def guid_to_string(binary_guid):
    import uuid
    return str(uuid.UUID(bytes_le=binary_guid)).lower()


# 如何通过微软active directory objectGUID 查询对象信息 
# bytes类型的 objectGUID 与十六进制 str类型 objectGUID 相互转换
objectGUID = b'Igr\xafb\x19ME\xb2P9c\xfb\xa0\xe2w'
str_hex_objectGUID = str(uuid.UUID(bytes=objectGUID).hex).upper() # '496772AF62194D45B2503963FBA0E277'
bytes_objectGUID = uuid.UUID(hex=str_hex_objectGUID).bytes # b'Igr\xafb\x19ME\xb2P9c\xfb\xa0\xe2w'

# str类型 objectGUID 转换为支持 ldap search filter的guid
guid = ''.join(['\\%s' % str_hex_objectGUID[i:i+2] for i in range(0, len(str_hex_objectGUID), 2)]) # '\\49\\67\\72\\AF\\62\\19\\4D\\45\\B2\\50\\39\\63\\FB\\A0\\E2\\77'

search_filter = ('(objectGUID=%s)' % guid)
ldap.conn.search_s(self.base_dn, user_scope, search_filter)
