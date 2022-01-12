#include <klee/klee.h>

#include <stdint.h>
// so we can copy/paste their code as is
typedef uint8_t uint8;
typedef uint32_t uint32;

// -- BEGIN COPY PASTED FIGURE 2 --

uint32 ct_lt(uint32 a, uint32 b) {
  uint32 c = a ^ ((a ^ b) | ((a - b) ^ b));
  return (0 - (c >> ( sizeof (c) * 8 - 1)));
}

void cp_copy_subarray(uint8 *out, const uint8 *in, uint32 len, uint32 l_idx, uint32 sub_len) {
  uint32 i, j, in_range;
  for (i=0;i<sub_len;i++) out[i]=0;
  for (i=0,j=0;i<len;i++) {
    in_range = 0;
    in_range |= ~ct_lt(i,l_idx);
    in_range &= ct_lt(i,l_idx+sub_len);
    out[j] |= in[i] & in_range;
    j = j + (in_range % 2);
  }
}

// -- END COPY PASTED FIGURE 2 --

int main()
{
  uint8_t in[20];
  klee_make_symbolic(in, sizeof(in), "in");

  uint8_t out[20];
  const uint32_t MAX_LEN=10;

  uint32_t l_idx = klee_range(0, sizeof(in)-MAX_LEN, "l_idx");
  uint32_t sub_len = klee_range(0, MAX_LEN, "sub_len");

  klee_set_taint(1, &l_idx, sizeof(l_idx));

  cp_copy_subarray(out, in, sizeof(in), l_idx, sub_len);

  return out[sizeof(out)/2];
}
