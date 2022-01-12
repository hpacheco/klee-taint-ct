/**
 * @author ntauth
 * @brief  ChaCha encryption harness for leakage analysis
 */

extern "C" {
#include <crypto/chacha.h>
}

#include <klee/klee.h>

int main(int argc, char **argv)
{
  constexpr size_t LO_BOUND = 5, HI_BOUND = 10;

  unsigned int key[8], nonce[4];
  unsigned char* inp_out;
  int bits, inp_out_size = 1;

  // Compute symbolic range for input/output size
  bits = klee_range(LO_BOUND, HI_BOUND + 1, "bits");

  for (int i = LO_BOUND; i <= HI_BOUND; i++) {
    if (bits == i)
      bits = i;
  }

  inp_out_size <<= bits;

  // Allocate buffers
  inp_out = new unsigned char[inp_out_size];

  // Make symbolic key and nonce
  klee_make_symbolic(key, sizeof(key), "key");
  klee_make_symbolic(nonce, sizeof(nonce), "nonce");

  // Taint secret data
  klee_set_taint(1, key, sizeof(key));
  klee_set_taint(1, nonce, sizeof(nonce));

  // Encrypt
  ChaCha20_ctr32(inp_out, inp_out, inp_out_size, key, nonce);

  return 0;
}