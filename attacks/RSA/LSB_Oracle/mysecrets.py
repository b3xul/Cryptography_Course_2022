#this is the file 2. in the current exercise but it is not
#allowed to have the "2." prefix if you want to use it as a module...

aes_key = b'\xf4/\xc6\x0b\xea\xc1w\xed\xfa\xf22\x0e\x92N8\x0e'
salsa_key = b'\xf4/\xc6\x0b\xea\xc1w\xed\xfa\xf22\x0e\x92N8\x0e'

bf_key = b'\x1e\x86\x114\x0b\x8d6k`\xb1\xdc\xb5\xa9\xc7,\xe8A\xe2\x1c\x0bk\x93Lc\xc0\xa9\xce\xae\xcc.z\xd2'
bf_iv = b'?y\xd5A9\x03Q\x91\xec\xdb\xe2F\xf9 \x92\xf8'

ecb_oracle_secret = "Here's my secret"
ecb_oracle_long_secret = "Here's my very long secret"
ecb_oracle_key = b'\x1e\x86\x114\x0b\x8d6k`\xb1\xdc\xb5\xa9\xc7,\xe8A\xe2\x1c\x0bk\x93Lc\xc0\xa9\xce\xae\xcc.z\xd2'

HOST = 'localhost'   # Symbolic name, meaning all available interfaces
PORT = 12342
cbc_oracle_key = b'0123456789abcdef0123456789abcdef'
cbc_oracle_iv = b'\xd9H\xaf\xc9\xa5\xc9"3\x93\xaa\xbd\x87\xa5\x15\x04\xdd'
# cbc_oracle_ciphertext = b'r\x8b\x14\xd6\xae{J\xa0\xe3\x9e\n\x96>\xf9=c\x0f\x16\x9at\x80\ny\xcfD\x08\xe7\xbe\xc1\x8d\x06U\x17J\xb4.\xe1\x9b48R\x8d\xd7\x04\xad\x0b\x7f\xbcS\xac\xd9\xb9\xbb\xfaI\x87\xa3E\x8aT8//\xf4\xb0\xa9u\x8c\x0eQ\x1c\x83v\xed\x04`\n\xf7\xcc\x03'
cbc_oracle_ciphertext = b'r\x8b\x14\xd6\xae{J\xa0\xe3\x9e\n\x96>\xf9=c\x0f\x16\x9at\x80\ny\xcfD\x08\xe7\xbe\xc1\x8d\x06U\x17J\xb4.\xe1\x9b48R\x8d\xd7\x04\xad\x0b\x7f\xbc\xa3{\xa1\x05_\xd5\xc0\xa4\xa0\xc5\xdaI\x11\xf3\x93\xb4'

rsa_key_pwd = 'this is the pwd'
rsa_msg = 'interesting msg'

lsb_n = 84512936364028707109792721541348089559038960317411172574310460131821809228801
lsb_d = 33338617022738821809198944565794469679031084241028925158776770023255471009649
lsb_e = 65537
lsb_ciphertext = 40905797042890600077330500098053021483209678644028914795144404253281221960366
lsb_plaintext = 803417515832054223369196934329960786582357242441556610682060160426930292
