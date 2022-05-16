#include <stdio.h>
#include <string.h>
#include <string>
#include <stdlib.h>
#include <time.h>

#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>

#include "ssl.h"


using namespace std;


void sha256(char *string, char outputBuffer[SHA256_DIGEST_LENGTH+1]) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, string, strlen(string));
    SHA256_Final(hash, &sha256);
    int i = 0;
    for(i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(outputBuffer + (i * 2), "%02x", hash[i]);
    }
    outputBuffer[SHA256_DIGEST_LENGTH] = 0;
}


string getTime() {
    static char buf[256];
    char fmt[] = "%a %b %d %H:%M:%S %Z %Y";
    time_t now = time(NULL);
    struct tm *tp;
    tp = localtime(&now);
    strftime(buf, sizeof(buf), fmt, tp);
    return buf;
}

int main(int argc, char **argv) {
    static string hello="Hello OpenSSL world "+getTime();
    static unsigned char buffer[65];

    char *chello = new char [hello.length()+1];
    std::strcpy (chello, hello.c_str());
    printf("%s\n", chello);
    sha256(chello, (char *)buffer);
    printf("sha256: %s\n", buffer);

    doTest();

    return 0;
}