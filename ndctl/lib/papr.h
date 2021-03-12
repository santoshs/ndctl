/* SPDX-License-Identifier: LGPL-2.1 */
/* (C) Copyright IBM 2020 */

#ifndef __PAPR_H__
#define __PAPR_H__

#include <papr_pdsm.h>

/* Wraps a nd_cmd generic header with pdsm header */
struct nd_pkg_papr {
	struct nd_cmd_pkg gen;
	struct nd_pkg_pdsm pdsm;
};

#define ND_PAPR_SMART_INJECT_MTEMP             (1 << 0)
#define ND_PAPR_SMART_INJECT_SPARES            (1 << 1)
#define ND_PAPR_SMART_INJECT_FATAL             (1 << 2)
#define ND_PAPR_SMART_INJECT_SHUTDOWN          (1 << 3)

#define ND_PAPR_HEALTH_SPARE_TRIP               (1 << 0)
#define ND_PAPR_HEALTH_TEMP_TRIP                (1 << 1)
#define ND_PAPR_HEALTH_CTEMP_TRIP               (1 << 2)

#endif /* __PAPR_H__ */
