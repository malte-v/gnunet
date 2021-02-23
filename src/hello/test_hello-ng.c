#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_nt_lib.h"
#include "gnunet_hello_lib.h"

int
main (int argc,
      char *argv[])
{
  struct GNUNET_CRYPTO_EddsaPublicKey pubKey;
  struct GNUNET_CRYPTO_EddsaPrivateKey privKey;
  struct GNUNET_PeerIdentity pid;
  struct GNUNET_TIME_Absolute t = GNUNET_TIME_absolute_get ();
  char *res;
  size_t res_len;
  enum GNUNET_NetworkType nt;

  GNUNET_CRYPTO_eddsa_key_create (&privKey);
  GNUNET_CRYPTO_eddsa_key_get_public (&privKey,
                                      &pubKey);
  pid.public_key = pubKey;
  GNUNET_HELLO_sign_address ("127.0.0.1:8080",
                             GNUNET_NT_LAN,
                             t,
                             &privKey,
                             (void**)&res,
                             &res_len);
  GNUNET_log (GNUNET_ERROR_TYPE_MESSAGE,
              "%s\n", res);
  GNUNET_assert (NULL !=
                 GNUNET_HELLO_extract_address ((void**)res,
                                               res_len,
                                               &pid,
                                               &nt,
                                               &t));
  return 0;
}
