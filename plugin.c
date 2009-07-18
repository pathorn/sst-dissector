/* Do not modify this file.  */
/* It is created automatically by the Makefile.  */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <gmodule.h>

/* Included *after* config.h, in order to re-define these macros */

#ifdef PACKAGE
#undef PACKAGE
#endif

/* Name of package */
#define PACKAGE "sst"


#ifdef VERSION
#undef VERSION
#endif

/* Version number of package */
#define VERSION "0.0.1"

#ifndef ENABLE_STATIC
G_MODULE_EXPORT const gchar version[] = VERSION;

/* Start the functions we need for the plugin stuff */

G_MODULE_EXPORT void
plugin_register (void)
{
  {extern void proto_register_sst (void); proto_register_sst ();}
}

G_MODULE_EXPORT void
plugin_reg_handoff(void)
{
  {extern void proto_reg_handoff_sst (void); proto_reg_handoff_sst ();}
}
#endif
