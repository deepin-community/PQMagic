/*
 * Build-time smoke test for the packaged public API.
 *
 * Upstream's own test programs all end in "return 0" regardless of what the
 * self-checks printed, so their exit status cannot be used by a build.  This
 * driver instead exercises the exported ABI through the header that the -dev
 * package installs, and fails the build on any mismatch.
 */

#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include <pqmagic_api.h>

static int failures;

static void
check(const char *what, int cond)
{
	if (!cond) {
		fprintf(stderr, "FAIL: %s\n", what);
		failures++;
	}
}

static void
test_ml_kem_512(void)
{
	unsigned char pk[ML_KEM_512_PUBLICKEYBYTES];
	unsigned char sk[ML_KEM_512_SECRETKEYBYTES];
	unsigned char ct[ML_KEM_512_CIPHERTEXTBYTES];
	unsigned char ss_enc[ML_KEM_512_SSBYTES];
	unsigned char ss_dec[ML_KEM_512_SSBYTES];

	check("ml_kem_512 keypair",
	      pqmagic_ml_kem_512_std_keypair(pk, sk) == 0);
	check("ml_kem_512 enc",
	      pqmagic_ml_kem_512_std_enc(ct, ss_enc, pk) == 0);
	check("ml_kem_512 dec",
	      pqmagic_ml_kem_512_std_dec(ss_dec, ct, sk) == 0);
	check("ml_kem_512 shared secret matches",
	      memcmp(ss_enc, ss_dec, ML_KEM_512_SSBYTES) == 0);

	/* A corrupted ciphertext must not yield the same secret. */
	ct[0] ^= 0x01;
	memset(ss_dec, 0, sizeof(ss_dec));
	pqmagic_ml_kem_512_std_dec(ss_dec, ct, sk);
	check("ml_kem_512 implicit rejection",
	      memcmp(ss_enc, ss_dec, ML_KEM_512_SSBYTES) != 0);
}

static void
test_ml_dsa_44(void)
{
	static const unsigned char msg[] = "pqmagic packaging smoke test";
	static const unsigned char ctx[] = "ctx";
	unsigned char pk[ML_DSA_44_PUBLICKEYBYTES];
	unsigned char sk[ML_DSA_44_SECRETKEYBYTES];
	unsigned char sig[ML_DSA_44_SIGBYTES];
	size_t siglen = 0;

	check("ml_dsa_44 keypair",
	      pqmagic_ml_dsa_44_std_keypair(pk, sk) == 0);
	check("ml_dsa_44 sign",
	      pqmagic_ml_dsa_44_std_signature(sig, &siglen,
					      msg, sizeof(msg) - 1,
					      ctx, sizeof(ctx) - 1, sk) == 0);
	check("ml_dsa_44 signature length",
	      siglen == ML_DSA_44_SIGBYTES);
	check("ml_dsa_44 verify",
	      pqmagic_ml_dsa_44_std_verify(sig, siglen,
					   msg, sizeof(msg) - 1,
					   ctx, sizeof(ctx) - 1, pk) == 0);

	/* A flipped bit must be rejected. */
	sig[0] ^= 0x01;
	check("ml_dsa_44 rejects modified signature",
	      pqmagic_ml_dsa_44_std_verify(sig, siglen,
					   msg, sizeof(msg) - 1,
					   ctx, sizeof(ctx) - 1, pk) != 0);
}

int
main(void)
{
	test_ml_kem_512();
	test_ml_dsa_44();

	if (failures) {
		fprintf(stderr, "smoke test: %d failure(s)\n", failures);
		return 1;
	}

	printf("smoke test: ML-KEM-512 and ML-DSA-44 round trips OK\n");
	return 0;
}
