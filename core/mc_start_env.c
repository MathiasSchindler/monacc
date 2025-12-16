#include "mc.h"

static char **g_mc_start_envp;

void mc_set_start_envp(char **envp) {
	g_mc_start_envp = envp;
}

char **mc_get_start_envp(void) {
	return g_mc_start_envp;
}
