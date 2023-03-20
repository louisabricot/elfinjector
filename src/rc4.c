#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef uint8_t byte;
#define N 256

static void	swap(byte* a, byte* b) {
	byte tmp = *a;
	*a = *b;
	*b = tmp;
}

// Key Scheduling Algorithm (KSA)
void	ksa(byte* S, const byte* key, const size_t key_length) {
	byte j = 0;

	for (int i = 0; i < N; i++) {
		S[i] = i;
	}

	for (int i = 0; i < N; i++) {
		j = (j + S[i] + key[i % key_length]) & 0xFF;
		swap(&S[i], &S[j]);
	}
}

// Pseudo-Random Generation Algorithm (PRGA)
void	prga(byte* S, byte* plaintext, const size_t length) {
	size_t i = 0;
	size_t j = 0;

	for (size_t n = 0; n < length; n++) {
		i = (i + 1) & 0xFF;
		j = (j + S[i]) & 0xFF;
		swap(&S[i], &S[j]);
		const int K = S[(S[i] + S[j]) & 0xFF];

		plaintext[n] ^= K;
	}
}

byte* rc4(const byte* key, const size_t key_length, byte* plaintext, const size_t text_length) {
	byte S[N];

	ksa(S, key, key_length);
	prga(S, plaintext, text_length);
	return (plaintext);
}

int main(int argc, char** argv) {
	byte	*key,
			*plaintext;
	size_t	key_length,
			plaintext_length;

	if(argc < 3) {
		printf("Usage: %s <key> <plaintext>", argv[0]);
		return -1;
	}
	key = (byte *)argv[1];
	key_length = strlen((const char *)key);
	plaintext = (byte *)argv[2];
	plaintext_length = strlen((const char *)plaintext);

	byte* ciphertext = rc4(key, key_length, plaintext, plaintext_length);

	for (size_t i = 0, len = plaintext_length; i < len; i++) {
		printf("%02hhX ", ciphertext[i]);
	}

	return (0);
}
