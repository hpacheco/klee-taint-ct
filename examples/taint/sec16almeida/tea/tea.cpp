#include "../verifying-constant-time/examples/tea/tea.c"

#include <klee/klee.h>

int main()
{
  uint32_t v[2];
  uint32_t k[4];

  klee_make_symbolic(&v, sizeof(v), "v");
  klee_make_symbolic(&k, sizeof(k), "k");

  uint32_t v_orig[2];
  v_orig[0] = v[0];
  v_orig[1] = v[1];

  klee_set_taint(1, &k, sizeof(k));

  encrypt(v, k);
  decrypt(v, k);

// these cause taint warnings because they turn into a conditional jump to assert fail
//  klee_assert(v_orig[0] == v[0]);
//  klee_assert(v_orig[1] == v[1]);

  return v[0] + v[1];
}
