from socket import socket
from OpenSSL import SSL,crypto
import os,re,sys
import urllib.request

class get_pem_ip:
    leaf_finger = 'services.tls.certificates.leaf_data.fingerprint:'
    chain_finger = 'services.tls.certificates.chain.fingerprint:'

    def __init__(self,host,port):
        self.host = host
        self.port = port

    def get_pem(self):
        pem = ''
        s = socket()
        ctx = SSL.Context(SSL.TLSv1_2_METHOD)
        cnt = SSL.Connection(ctx, s)
        cnt.connect((self.host, self.port))
        cnt.do_handshake()
        certs = cnt.get_peer_cert_chain()
        for number, cert in enumerate(certs[0:1]):
            cert_ = dict(cert.get_subject().get_components())
            cn = (cert_.get(b'CN')).decode('utf-8')
            pem = (crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode('utf-8'))
        w = open(os.getcwd() + '/cert/' + self.host + ".pem", "w+")
        w.write(pem)
        w.close()

    def get_finger(self):
        cmd_ = "openssl x509 -in " + os.getcwd() + '/cert/' + self.host + ".pem" + " -fingerprint -sha256"
        result = os.popen(cmd_)
        temp = result.readline()
        temp = str(re.findall(r"Fingerprint=(.+)", temp))
        cert_sha256 = temp.replace(":", "").replace("'", "").replace("[", "").replace("]", "")
        cert_sha256 = cert_sha256.lower()
        print("证书指纹（sha256）：")
        print(cert_sha256)
        data_finger = self.leaf_finger + cert_sha256 + '+or+' + self.chain_finger + cert_sha256
        return data_finger

    def get_ip(self,data_finger):
        url = 'https://search.censys.io/_search?resource=hosts&per_page=50&virtual_hosts=EXCLUDE&q='
        url = url + data_finger
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:94.0)", "Host": "search.censys.io",
                   "Connection": "close"}
        request = urllib.request.Request(url=url, headers=headers, method='GET')
        response = urllib.request.urlopen(request)
        html = response.readline().decode('utf-8')
        print("通过证书反查到的IP：")
        while html:
            html = response.readline().decode('utf-8')
            ip = re.findall("\<strong\>(.*?)\<\/strong\>", html)
            if ip:
                print(str(ip).replace(":", "").replace("'", "").replace("[", "").replace("]", ""))

host = sys.argv[1]
port = sys.argv[2]
port = int(port)
c1 = get_pem_ip(host,port)
c1.get_pem()
c1.get_ip(data_finger=c1.get_finger())
