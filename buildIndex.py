from pybloom_live.pybloom import BloomFilter # bloom filter, the package is pybloom_live
import parse_doc_to_dict
import redis
import AES
import hashlib
import keyGen
import time




def build_index(db, key_kw, key_xtrap, capacity, request_error_rate):
   # 这个形式为{id: [kw1, kw2 ....]}
    processed_data = parse_doc_to_dict.preprocess_data(db)

    # parse original data to keyword_doc_map
    wordDoc_to_map = parse_doc_to_dict.generate_inverted_index(processed_data)

    time_start = time.perf_counter()  # 记录开始时间
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

        for id in id_list:
            h_id = hashlib.sha256(bytes(id))
            e = AES.aes_encrypt(k_e[0], h_id.digest())
            xtag = AES.aes_encrypt(xtrap[0], h_id.digest())
            XSet.add(xtag[0])
            t.append(e[0])
        TSet.setdefault(k_e[0], t)
        TSet1.set(k_e[0], t)
    time_end = time.perf_counter()  # 记录结束时间

    run_time = time_end - time_start

    return TSet, TSet1, XSet, run_time







if __name__ == "__main__":
    db = "/home/cysren/Desktop/lilvmy/Tfvt/cranfieldDocs"
    data = parse_doc_to_dict.read_data(db)
    sk_DO, pk_DO, sk_U, pk_U = keyGen.generate_ec_key()
    shared_docCntW_key, shared_w_key, share_xtrap_key, shared_role_key = keyGen.derive_shared_key(sk_DO, pk_DO, sk_U, pk_U)
    capacity = 100000
    request_error_rate = 0.0001


    TSet, TSet1, XSet, run_time = build_index(data, shared_w_key, share_xtrap_key, capacity, request_error_rate)
    # filename = open('/home/cysren/Desktop/lilvmy/Tfvt/TSet.txt','w')#dict转txt
    # for k,v in TSet.items():
    #     filename.write(str(k)+':'+str(v))
    #     filename.write('\n')
    # filename.close()
    print(run_time * 1000)
