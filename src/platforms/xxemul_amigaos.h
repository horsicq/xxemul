#ifndef XXEMUL_AMIGAOS_H
#define XXEMUL_AMIGAOS_H
#include "xxemul/xxemul.h"
typedef struct xxemul_amigaos xxemul_amigaos;
xxemul_status xxemul_amigaos_start(xxemul *e, const char *program, const char *workdir, int argc, const char *const *argv);
void xxemul_amigaos_destroy(xxemul_amigaos *p);
int xxemul_amigaos_exit_code(const xxemul_amigaos *p);
const char *xxemul_amigaos_error(const xxemul_amigaos *p);
const char *xxemul_amigaos_symbol(const xxemul_amigaos *p, uint64_t address);
xxemul_status xxemul_amigaos_after_step(const xxemul_amigaos *p, xxemul_status status);
#endif
