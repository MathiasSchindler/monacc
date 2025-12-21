#include "mc.h"

#if MC_OS_DARWIN
extern char **environ;
#endif

static char **g_mc_start_envp;

void mc_set_start_envp(char **envp) {
	g_mc_start_envp = envp;
}

char **mc_get_start_envp(void) {
	#if MC_OS_DARWIN
	if (!g_mc_start_envp) return environ;
	#endif
	return g_mc_start_envp;
}

