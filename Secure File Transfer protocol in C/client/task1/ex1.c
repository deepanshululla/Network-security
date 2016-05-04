#include <stdio.h>
#include <string.h>

/* Opens ssl headers */

# include "openssl/bio.h"
# include "openssl/ssl.h"
# include "openssl/err.h"
# include "openssl/bn.h"
#include <openssl/dh.h>
#include <openssl/pem.h>



/*Initializing openssl*/

/* Initializing openssl */

SSL_load_error_strings();
ERR_load_BIO_strings();
OpenSSL_add_all_algorithms();

BIO *bio;





