#include <cstdio>
#include <iostream>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/opensslv.h>

static BIO * bio_err = NULL;
static BIO * bio_out = NULL;

static int genrsa_cb(int p, int n, BN_GENCB *cb);

/* Generates a 2048-bit RSA key. */
EVP_PKEY * generate_key(int keySize)
{
    /* Allocate memory for the EVP_PKEY structure. */
    EVP_PKEY * pkey = EVP_PKEY_new();
    if(!pkey)
    {
        return NULL;
    }
    
    /* Generate the RSA key and assign it to pkey. */
    RSA *rsa = RSA_new();
    BIGNUM *bn = BN_new();
    BN_GENCB *cb = BN_GENCB_new();
    int num = 2048;
    int primes = 2;
    int f4 = RSA_F4;

    BN_GENCB_set(cb, genrsa_cb, bio_err);

    if (!BN_set_word(bn, f4)
        || !RSA_generate_multi_prime_key(rsa, num, primes, bn, cb)) 
    {
        EVP_PKEY_free(pkey);
        return NULL;
    }

    if(!EVP_PKEY_assign_RSA(pkey, rsa))
    {
        EVP_PKEY_free(pkey);
        return NULL;
    }
    
    /* The key has been generated, return it. */
    return pkey;
}

/* Generates a self-signed x509 certificate. */
X509 * generate_x509(EVP_PKEY * pkey, char *commonName)
{
    /* Allocate memory for the X509 structure. */
    X509 * x509 = X509_new();
    if(!x509)
    {
        return NULL;
    }
    
    /* Set the serial number. */
    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
    
    /* This certificate is valid from now until exactly one year from now. */
    time_t t;
    t = time(NULL);
    X509_set1_notBefore(x509, ASN1_UTCTIME_adj(NULL, t, 0, 0L));
    X509_set1_notAfter(x509, ASN1_UTCTIME_adj(NULL, t, 365, 0L));
    
    /* Set the public key for our certificate. */
    X509_set_pubkey(x509, pkey);
    
    /* We want to copy the subject name to the issuer name. */
    X509_NAME * name = X509_get_subject_name(x509);
    
    /* Set the country code and common name. */
    X509_NAME_add_entry_by_txt(name, "C",  MBSTRING_ASC, (unsigned char *)"BE",  -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O",  MBSTRING_ASC, (unsigned char *)"MyCompany", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)commonName, -1, -1, 0);
    
    /* Now set the issuer name. */
    X509_set_issuer_name(x509, name);
    
    /* Actually sign the certificate with our key. */
    if(!X509_sign(x509, pkey, EVP_sha256()))
    {
        X509_free(x509);
        return NULL;
    }
    
    return x509;
}

bool write_to_stdout(EVP_PKEY * pkey, X509 * x509)
{
    /* Write the key to disk. */
    bool ret = PEM_write_bio_PrivateKey(bio_out, pkey, NULL, NULL, 0, NULL, NULL);
    
    if(!ret)
    {
        return false;
    }
    
    /* Write the certificate to disk. */
    ret = PEM_write_bio_X509(bio_out, x509);
    
    if(!ret)
    {
        return false;
    }

    /* Write the certificate to disk. */
    ret = X509_print(bio_out, x509);
    
    if(!ret)
    {
        return false;
    }

    return true;
}

bool write_to_buffer(EVP_PKEY * pkey, X509 * x509, void(*f)(char *cert, char *pkey))
{
    BIO *certif = BIO_new(BIO_s_mem());
    BIO *privKey = BIO_new(BIO_s_mem());
    char *certif_buf = NULL;
    long certif_buf_lg = 0;
    char *privKey_buf = NULL;
    long privKey_buf_lg = 0;

    /* Write the key to disk. */
    bool ret = PEM_write_bio_PrivateKey(privKey, pkey, NULL, NULL, 0, NULL, NULL);
    if(!ret)
    {
        return false;
    }
    
    /* Write the certificate to disk. */
    ret = PEM_write_bio_X509(certif, x509);
    if(!ret)
    {
        return false;
    }

    privKey_buf_lg = BIO_get_mem_data(privKey, &privKey_buf);

    certif_buf_lg = BIO_get_mem_data(certif, &certif_buf);

    std::cout << "Calling callback function ..." << std::endl;

    // Callback the function
    (*f)(certif_buf, privKey_buf);

    BIO_free(privKey);
    BIO_free(certif);

    return true;
}

extern "C" {

    int doTest(void(*f)(char *cert, char *pkey))
    {
        std::cout << OpenSSL_version(OPENSSL_FULL_VERSION_STRING) << std::endl;

        if (!bio_err) {
            bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);
        }
        if (!bio_out) {
            bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);
        }

        /* Generate the key. */
        std::cout << "Generating RSA key..." << std::endl;
        
        EVP_PKEY * pkey = generate_key(4096);
        if(!pkey)
            return 1;
        
        /* Generate the certificate. */
        std::cout << "Generating x509 certificate..." << std::endl;
        
        X509 * x509 = generate_x509(pkey, (char *)"Test User 1");
        if(!x509)
        {
            EVP_PKEY_free(pkey);
            return 1;
        }
        
        /* Write the private key and certificate out to disk. */
        std::cout << "Writing key and certificate to stdout..." << std::endl;
        
        bool ret1 = 1; // write_to_stdout(pkey, x509);

        bool ret2 = write_to_buffer(pkey, x509, f);

        EVP_PKEY_free(pkey);
        X509_free(x509);
        
        if(ret1 && ret2)
        {
            std::cout << "Success!" << std::endl;
            return 0;
        }
        else
            return 1;
    }

}

int ctr = 0;

static int genrsa_cb(int p, int n, BN_GENCB *cb)
{
    char c = '*';

    if (p == 0)
        c = '.';
    if (p == 1)
        c = '+';
    if (p == 2)
        c = '*';
    if (p == 3)
        c = '-';
    BIO_write(bio_out, &c, 1);
    if ((ctr % 80) == 0) {
        BIO_write(bio_out, "\n", 1);
        ctr = 0;
    }
    (void)BIO_flush(bio_out);
    ctr++;
    return 1;
}