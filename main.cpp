#include <iostream>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>


#include <errno.h>
#include <unistd.h>
using namespace std;


void printCert(X509* cert) {
    cout << "Subject: ";

    char* data = strtok(cert->name, "/");
    cout << data;
    data = strtok(NULL, "/");
    while(data != NULL) {
        cout << ", " << data;
        data = strtok(NULL, "/");
    }
    cout << endl;

    BIO * issuerData = BIO_new(BIO_s_mem());
    X509_NAME_print(issuerData,X509_get_issuer_name(cert),0);
    BUF_MEM *issuerMem;
    BIO_get_mem_ptr(issuerData, &issuerMem);


    cout << "Issuer: ";
    data = strtok(issuerMem->data, "/");
    cout << data;
    data = strtok(NULL, "/");
    while(data != NULL) {
        cout << ", " << data;
        data = strtok(NULL, "/");
    }
    cout << endl;

    BIO_free(issuerData);
}

int main(int argc, char* argv[]) {
    X509* cert;
    SSL* ssl;
    SSL_CTX * ctx;
    struct sockaddr_in address;
    struct hostent* h;
    char* host;
    int id;



    if(argc != 2) {
        cerr << "Supply hostname as an argument!" << endl;
        exit(1);
    }


    host = (char*)malloc(strlen(argv[1]) - 8);
    int pos = strstr(argv[1], "https://") - argv[1];
    if(pos != 0) {
        cerr << "Host must be in format: 'https://location'" << endl;
        exit(1);
    }
    int n = strlen(argv[1]);
    if(n >= 8) {
        memcpy(host, argv[1] + 8, n - 8);
    }
    host[n - 8] = '\0';


    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    ctx = SSL_CTX_new(SSLv23_client_method());
    if(ctx == NULL) {
        ERR_print_errors_fp(stderr);
        exit(2);
    }

    h = gethostbyname(host);

    if(h == NULL) {
        cerr << "Error: Incorrect hostname supplied!" << endl;
        exit(3);
    }

    id = socket(PF_INET, SOCK_STREAM, 0);

    bzero(&address, sizeof(address));

    address.sin_family = AF_INET;
    address.sin_port = htons(443);
    address.sin_addr.s_addr = *(long*)(h->h_addr);

    if(connect(id, (struct sockaddr*)&address, sizeof(address)) != 0) {
        close(id);
        cerr << "Error while connecting to server..." << endl;
        exit(4);
    } else {
        cout << "Successful TCP connection to " << argv[1] << "." << endl;
    }


    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, id);

    if(SSL_connect(ssl)) {
        cout << "Successful SSL/TLS connection to " << argv[1] << "." << endl;
        cert = SSL_get_peer_certificate(ssl);
        printCert(cert);
        SSL_free(ssl);
        cout << "SSL/TLS session_terminated: " << argv[1] << "."<<endl;
    } else {
        ERR_print_errors_fp(stdin);
        exit(5);
    }

    close(id);
    SSL_CTX_free(ctx);

    return 0;
}



