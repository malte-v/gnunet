/*
     This file is part of GNUnet.
     Copyright (C) 2020 GNUnet e.V.

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU Affero General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.

     You should have received a copy of the GNU Affero General Public License
     along with this program.  If not, see <http://www.gnu.org/licenses/>.

     SPDX-License-Identifier: AGPL3.0-or-later
 */

/**
 * @file util/gnunet-crypto-tgv.c
 * @brief Generate test vectors for cryptographic operations.
 * @author Florian Dold
 *
 * Test vectors have the following format (TypeScript pseudo code):
 *
 * interface TestVectorFile {
 *   encoding: "base32crockford";
 *   producer?: string;
 *   vectors: TestVector[];
 * }
 *
 * enum Operation {
 *  Hash("hash"),
 *  ...
 * }
 *
 * interface TestVector {
 *   operation: Operation;
 *   // Inputs for the operation
 *   [ k: string]: string | number;
 * };
 *
 *
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_signatures.h"
#include "gnunet_testing_lib.h"
#include <jansson.h>
#include <gcrypt.h>

GNUNET_NETWORK_STRUCT_BEGIN

/**
 * Sample signature struct.
 *
 * Purpose is #GNUNET_SIGNATURE_PURPOSE_TEST
 */
struct TestSignatureDataPS
{
  struct GNUNET_CRYPTO_EccSignaturePurpose purpose;
  uint32_t testval;
};

GNUNET_NETWORK_STRUCT_END


/**
 * Create a fresh test vector for a given operation label.
 *
 * @param vecs array of vectors to append the new vector to
 * @param vecname label for the operation of the vector
 * @returns the fresh test vector
 */
static json_t *
vec_for (json_t *vecs, const char *vecname)
{
  json_t *t = json_object ();

  json_object_set_new (t,
                       "operation",
                       json_string (vecname));
  json_array_append_new (vecs, t);
  return t;
}


/**
 * Add a base32crockford encoded value
 * to a test vector.
 *
 * @param vec test vector to add to
 * @param label label for the value
 * @param data data to add
 * @param size size of data
 */
static void
d2j (json_t *vec,
     const char *label,
     const void *data,
     size_t size)
{
  char *buf;
  json_t *json;

  buf = GNUNET_STRINGS_data_to_string_alloc (data, size);
  json = json_string (buf);
  GNUNET_free (buf);
  GNUNET_break (NULL != json);

  json_object_set_new (vec, label, json);
}

/**
 * Add a number to a test vector.
 *
 * @param vec test vector to add to
 * @param label label for the value
 * @param data data to add
 * @param size size of data
 */
static void
uint2j (json_t *vec,
     const char *label,
     unsigned int num)
{
  json_t *json = json_integer (num);

  json_object_set_new (vec, label, json);
}

/**
 * Main function that will be run.
 *
 * @param cls closure
 * @param args remaining command-line arguments
 * @param cfgfile name of the configuration file used (for saving, can be NULL!)
 * @param cfg configuration
 */
static void
run (void *cls,
     char *const *args,
     const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  json_t *vecfile = json_object ();
  json_t *vecs = json_array ();

  json_object_set_new (vecfile,
                       "encoding",
                       json_string ("base32crockford"));
  json_object_set_new (vecfile,
                       "producer",
                       json_string ("GNUnet " PACKAGE_VERSION " " VCS_VERSION));
  json_object_set_new (vecfile,
                       "vectors",
                       vecs);

  {
    json_t *vec = vec_for (vecs, "hash");
    struct GNUNET_HashCode hc;
    char *str = "Hello, GNUnet";

    GNUNET_CRYPTO_hash (str, strlen (str), &hc);

    d2j (vec, "input", str, strlen (str));
    d2j (vec, "output", &hc, sizeof (struct GNUNET_HashCode));
  }
  {
    json_t *vec = vec_for (vecs, "ecdhe_key_derivation");
    struct GNUNET_CRYPTO_EcdhePrivateKey priv1;
    struct GNUNET_CRYPTO_EcdhePublicKey pub1;
    struct GNUNET_CRYPTO_EcdhePrivateKey priv2;
    struct GNUNET_HashCode skm;

    GNUNET_CRYPTO_ecdhe_key_create (&priv1);
    GNUNET_CRYPTO_ecdhe_key_create (&priv2);
    GNUNET_CRYPTO_ecdhe_key_get_public (&priv1,
                                        &pub1);
    GNUNET_assert (GNUNET_OK ==
                   GNUNET_CRYPTO_ecc_ecdh (&priv2,
                                           &pub1,
                                           &skm));

    d2j (vec,
         "priv1",
         &priv1,
         sizeof (struct GNUNET_CRYPTO_EcdhePrivateKey));
    d2j (vec,
         "pub1",
         &pub1,
         sizeof (struct GNUNET_CRYPTO_EcdhePublicKey));
    d2j (vec,
         "priv2",
         &priv2,
         sizeof (struct GNUNET_CRYPTO_EcdhePrivateKey));
    d2j (vec,
         "skm",
         &skm,
         sizeof (struct GNUNET_HashCode));
  }

  {
    json_t *vec = vec_for (vecs, "eddsa_key_derivation");
    struct GNUNET_CRYPTO_EddsaPrivateKey priv;
    struct GNUNET_CRYPTO_EddsaPublicKey pub;

    GNUNET_CRYPTO_eddsa_key_create (&priv);
    GNUNET_CRYPTO_eddsa_key_get_public (&priv,
                                        &pub);

    d2j (vec,
         "priv",
         &priv,
         sizeof (struct GNUNET_CRYPTO_EddsaPrivateKey));
    d2j (vec,
         "pub",
         &pub,
         sizeof (struct GNUNET_CRYPTO_EddsaPublicKey));
  }
  {
    json_t *vec = vec_for (vecs, "eddsa_signing");
    struct GNUNET_CRYPTO_EddsaPrivateKey priv;
    struct GNUNET_CRYPTO_EddsaPublicKey pub;
    struct GNUNET_CRYPTO_EddsaSignature sig;
    struct TestSignatureDataPS data = { 0 };

    GNUNET_CRYPTO_eddsa_key_create (&priv);
    GNUNET_CRYPTO_eddsa_key_get_public (&priv,
                                        &pub);
    data.purpose.size = htonl (sizeof (data));
    data.purpose.purpose = htonl (GNUNET_SIGNATURE_PURPOSE_TEST);
    GNUNET_CRYPTO_eddsa_sign (&priv,
                              &data,
                              &sig);
    GNUNET_assert (GNUNET_OK ==
                   GNUNET_CRYPTO_eddsa_verify (GNUNET_SIGNATURE_PURPOSE_TEST,
                                               &data,
                                               &sig,
                                               &pub));

    d2j (vec,
         "priv",
         &priv,
         sizeof (struct GNUNET_CRYPTO_EddsaPrivateKey));
    d2j (vec,
         "pub",
         &pub,
         sizeof (struct GNUNET_CRYPTO_EddsaPublicKey));
    d2j (vec,
         "data",
         &data,
         sizeof (struct TestSignatureDataPS));
    d2j (vec,
         "sig",
         &sig,
         sizeof (struct GNUNET_CRYPTO_EddsaSignature));
  }

  {
    json_t *vec = vec_for (vecs, "kdf");
    size_t out_len = 64;
    char out[out_len];
    char *ikm = "I'm the secret input key material";
    char *salt = "I'm very salty";
    char *ctx = "I'm a context chunk, also known as 'info' in the RFC";

    GNUNET_assert (GNUNET_OK ==
                   GNUNET_CRYPTO_kdf (&out,
                                      out_len,
                                      salt,
                                      strlen (salt),
                                      ikm,
                                      strlen (ikm),
                                      ctx,
                                      strlen (ctx),
                                      NULL));

    d2j (vec,
         "salt",
         salt,
         strlen (salt));
    d2j (vec,
         "ikm",
         ikm,
         strlen (ikm));
    d2j (vec,
         "ctx",
         ctx,
         strlen (ctx));
    uint2j (vec,
            "out_len %u\n",
            (unsigned int) out_len);
    d2j (vec,
         "out",
         out,
         out_len);
  }
  {
    json_t *vec = vec_for (vecs, "eddsa_ecdh");
    struct GNUNET_CRYPTO_EcdhePrivateKey priv_ecdhe;
    struct GNUNET_CRYPTO_EcdhePublicKey pub_ecdhe;
    struct GNUNET_CRYPTO_EddsaPrivateKey priv_eddsa;
    struct GNUNET_CRYPTO_EddsaPublicKey pub_eddsa;
    struct GNUNET_HashCode key_material;

    GNUNET_CRYPTO_ecdhe_key_create (&priv_ecdhe);
    GNUNET_CRYPTO_ecdhe_key_get_public (&priv_ecdhe, &pub_ecdhe);
    GNUNET_CRYPTO_eddsa_key_create (&priv_eddsa);
    GNUNET_CRYPTO_eddsa_key_get_public (&priv_eddsa, &pub_eddsa);
    GNUNET_CRYPTO_ecdh_eddsa (&priv_ecdhe, &pub_eddsa, &key_material);

    d2j (vec, "priv_ecdhe",
                  &priv_ecdhe,
                  sizeof (struct GNUNET_CRYPTO_EcdhePrivateKey));
    d2j (vec, "pub_ecdhe",
                  &pub_ecdhe,
                  sizeof (struct GNUNET_CRYPTO_EcdhePublicKey));
    d2j (vec, "priv_eddsa",
                  &priv_eddsa,
                  sizeof (struct GNUNET_CRYPTO_EddsaPrivateKey));
    d2j (vec, "pub_eddsa",
                  &pub_eddsa,
                  sizeof (struct GNUNET_CRYPTO_EddsaPublicKey));
    d2j (vec, "key_material",
                  &key_material,
                  sizeof (struct GNUNET_HashCode));
  }

  {
    json_t *vec = vec_for (vecs, "rsa_blind_signing");

    struct GNUNET_CRYPTO_RsaPrivateKey *skey;
    struct GNUNET_CRYPTO_RsaPublicKey *pkey;
    struct GNUNET_HashCode message_hash;
    struct GNUNET_CRYPTO_RsaBlindingKeySecret bks;
    struct GNUNET_CRYPTO_RsaSignature *blinded_sig;
    struct GNUNET_CRYPTO_RsaSignature *sig;
    void *blinded_data;
    size_t blinded_len;
    void *public_enc_data;
    size_t public_enc_len;
    void *blinded_sig_enc_data;
    size_t blinded_sig_enc_length;
    void *sig_enc_data;
    size_t sig_enc_length;

    skey = GNUNET_CRYPTO_rsa_private_key_create (2048);
    pkey = GNUNET_CRYPTO_rsa_private_key_get_public (skey);
    GNUNET_CRYPTO_random_block (GNUNET_CRYPTO_QUALITY_WEAK,
                                &message_hash,
                                sizeof (struct GNUNET_HashCode));
    GNUNET_CRYPTO_random_block (GNUNET_CRYPTO_QUALITY_WEAK,
                                &bks,
                                sizeof (struct
                                        GNUNET_CRYPTO_RsaBlindingKeySecret));
    GNUNET_assert (GNUNET_YES ==
                   GNUNET_CRYPTO_rsa_blind (&message_hash,
                                            &bks,
                                            pkey,
                                            &blinded_data,
                                            &blinded_len));
    blinded_sig = GNUNET_CRYPTO_rsa_sign_blinded (skey, blinded_data,
                                                  blinded_len);
    sig = GNUNET_CRYPTO_rsa_unblind (blinded_sig, &bks, pkey);
    GNUNET_assert (GNUNET_YES == GNUNET_CRYPTO_rsa_verify (&message_hash, sig,
                                                           pkey));
    public_enc_len = GNUNET_CRYPTO_rsa_public_key_encode (pkey,
                                                          &public_enc_data);
    blinded_sig_enc_length = GNUNET_CRYPTO_rsa_signature_encode (blinded_sig,
                                                                 &
                                                                 blinded_sig_enc_data);
    sig_enc_length = GNUNET_CRYPTO_rsa_signature_encode (sig, &sig_enc_data);
    d2j (vec,
         "message_hash",
         &message_hash,
         sizeof (struct GNUNET_HashCode));
    d2j (vec,
         "rsa_public_key",
         public_enc_data,
         public_enc_len);
    d2j (vec,
         "blinding_key_secret",
         &bks,
         sizeof (struct GNUNET_CRYPTO_RsaBlindingKeySecret));
    d2j (vec,
         "blinded_message",
         blinded_data,
         blinded_len);
    d2j (vec,
         "blinded_sig",
         blinded_sig_enc_data,
         blinded_sig_enc_length);
    d2j (vec,
         "sig",
         sig_enc_data,
         sig_enc_length);
    GNUNET_CRYPTO_rsa_private_key_free (skey);
    GNUNET_CRYPTO_rsa_public_key_free (pkey);
    GNUNET_CRYPTO_rsa_signature_free (sig);
    GNUNET_CRYPTO_rsa_signature_free (blinded_sig);
    GNUNET_free (public_enc_data);
    GNUNET_free (blinded_data);
    GNUNET_free (sig_enc_data);
    GNUNET_free (blinded_sig_enc_data);
  }

  json_dumpf (vecfile, stdout, JSON_INDENT (2));
  json_decref (vecfile);
  printf ("\n");
}


/**
 * The main function of the test vector generation tool.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc,
      char *const *argv)
{
  const struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };

  GNUNET_assert (GNUNET_OK ==
                 GNUNET_log_setup ("gnunet-crypto-tvg",
                                   "INFO",
                                   NULL));
  if (GNUNET_OK !=
      GNUNET_PROGRAM_run (argc, argv,
                          "gnunet-crypto-tvg",
                          "Generate test vectors for cryptographic operations",
                          options,
                          &run, NULL))
    return 1;
  return 0;
}


/* end of gnunet-crypto-tvg.c */
