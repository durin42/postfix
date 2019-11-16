#include <fuzzer/FuzzedDataProvider.h>
#include <iostream>
#include <string>

extern "C" {

#include "../global/tok822.h"
#include "../util/sys_defs.h"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  FuzzedDataProvider provider(Data, Size);
  int limit = provider.ConsumeIntegralInRange(0, 100);
  std::string input = provider.ConsumeRemainingBytesAsString();
  TOK822 *result = tok822_parse_limit(input.c_str(), limit);
  if (result) {
    VSTRING *vp = vstring_alloc(100);
    // poke at the result a little before we throw it away
    vstring_str(tok822_internalize(vp, result, TOK822_STR_DEFL));
    vstring_str(tok822_externalize(
        vp, result, TOK822_STR_DEFL | TOK822_STR_LINE | TOK822_STR_TRNC));
    vstring_free(vp);
    tok822_free_tree(result);
  }
  return 0;
}
}
