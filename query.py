import AES
import keyGen

def user_query(cnt_W, query_kws, role, key_w, key_xtrap, key_role):
    # 初始化最小值和对应字符串的变量
    min_value = float('inf')  # 初始值设为正无穷
    min_string = None

    # 遍历查询关键字列表，查找最小值和对应的关键字
    for kw in query_kws:
        if kw in cnt_W:
            value = cnt_W[kw]
            if value < min_value:
                min_value = value
                min_string = kw

    remove_min_string_kws = query_kws.remove(min_string)
    stag = AES.aes_encrypt(key_w, bytes(min_string.encode('utf-8')))
    E_role = AES.aes_encrypt(key_role, bytes(role.encode('utf-8')))
    xtrap_q = []
    for remmain_kw in remove_min_string_kws:
        tmp = AES.aes_encrypt(key_xtrap, bytes(remmain_kw.encode('utf-8')))
        xtrap_q.append(tmp)

    return stag, E_role, xtrap_q