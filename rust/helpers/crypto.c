// SPDX-License-Identifier: GPL-2.0

#include <crypto/hash.h>

#ifdef CONFIG_CRYPTO
void rust_helper_crypto_free_shash(struct crypto_shash *tfm)
{
	crypto_free_shash(tfm);
}

unsigned int rust_helper_crypto_shash_digestsize(struct crypto_shash *tfm)
{
	return crypto_shash_digestsize(tfm);
}

unsigned int rust_helper_crypto_shash_descsize(struct crypto_shash *tfm)
{
	return crypto_shash_descsize(tfm);
}

int rust_helper_crypto_shash_init(struct shash_desc *desc)
{
	return crypto_shash_init(desc);
}
#endif
