from pybloom_live.pybloom import BloomFilter # bloom filter, the package is pybloom_live
import redis
import AES
import hashlib
import keyGen
import time
import parse_doc_to_dict as pa

def build_index(wordDoc_to_map, key_kw, key_xtrap, capacity, request_error_rate):

    time_start = time.perf_counter()  # 记录开始时间

    # counter-the user use it to find the low frequency keyword in his/her query
    E_cnt = {}

    # dictionary
    TSet = {}

    # redis-py 使用 connection pool 来管理对一个 redis server 的所有连接，避免每次建立、释放连接的开销。
    pool = redis.ConnectionPool(host='localhost', port=6379, decode_responses=True)
    TSet1 = redis.StrictRedis(host='localhost', port=6379, db=0, decode_responses=True)

    # bloom filter
    XSet = BloomFilter(capacity=capacity, error_rate = request_error_rate)

    for w, id_list in wordDoc_to_map.items():
        # store encryption id
        t = []
        # encrypt keyword
        k_e = AES.aes_encrypt(key_kw, bytes(w.encode('utf-8')))
        xtrap = AES.aes_encrypt(key_xtrap, bytes(w.encode('utf-8')))
        cnt = 0
        for id in id_list:
            h_id = hashlib.sha256(bytes(str(id).encode('utf-8')))
            e = AES.aes_encrypt(k_e[0], h_id.digest())
            xtag = AES.aes_encrypt(xtrap[0], h_id.digest())
            XSet.add(xtag[0])
            t.append(e[0])
            cnt = cnt + 1
        TSet.setdefault(k_e[0], t)
        TSet1.set(k_e[0], t)

        E_cnt.setdefault(w, cnt)

        # 设置过期时间为 60秒,实际上只有几毫秒
        TSet1.expire(k_e[0], 60)
    time_end = time.perf_counter()  # 记录结束时间

    run_time = time_end - time_start

    savefile(E_cnt)

    return TSet, TSet1, XSet, run_time

def savefile(filename):
    fileadd = open('/home/cysren/Desktop/lilvmy/Tfvt/cnt_W.txt','w')
    for k,v in filename.items():
        fileadd.write(str(k) + ':' + str(v))
        # fileadd.write(str(k))
        fileadd.write('\n')
    fileadd.close()

if __name__ == "__main__":
    data = pa.read_data("/home/cysren/Desktop/lilvmy/Tfvt/cranfieldDocs")
    preprocessed_data = pa.preprocess_data(data)
    data_dict = pa.generate_inverted_index(preprocessed_data)
    # myfile = open("/home/cysren/Desktop/lilvmy/Tfvt/kw_ids_map.txt", 'r')
    # data_dict = {}
    # for line in myfile:
    #     k, v = line.strip().split(":")
    #     data_dict[k.strip()] = v.strip()
    #
    # myfile.close()

    sk_DO, pk_DO, sk_U, pk_U = keyGen.generate_ec_key()
    shared_docCntW_key, shared_w_key, share_xtrap_key, shared_role_key = keyGen.derive_shared_key(sk_DO, pk_DO, sk_U, pk_U)
    capacity = 1000000000
    request_error_rate = 0.0001


    TSet, TSet1, XSet, run_time = build_index(data_dict, shared_w_key, share_xtrap_key, capacity, request_error_rate)
    # filename = open('/home/cysren/Desktop/lilvmy/Tfvt/TSet.txt','w')#dict转txt
    # for k,v in TSet.items():
    #     filename.write(str(k)+':'+str(v))
    #     filename.write('\n')
    # filename.close()
    print(run_time * 1000)
