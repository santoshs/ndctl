// SPDX-License-Identifier: LGPL-2.1
/*
 * libndctl support for PAPR-SCM based NVDIMMs
 *
 * (C) Copyright IBM 2020
 *
 */

#include <stdint.h>
#include <stdlib.h>
#include <limits.h>
#include <util/log.h>
#include <ndctl.h>
#include <ndctl/libndctl.h>
#include <lib/private.h>
#include "papr.h"

/* Utility logging maros for simplify logging */
#define papr_dbg(_dimm, _format_str, ...) dbg(_dimm->bus->ctx,		\
					      "%s:" _format_str,	\
					      ndctl_dimm_get_devname(_dimm), \
					      ##__VA_ARGS__)

#define papr_err(_dimm, _format_str, ...) err(_dimm->bus->ctx,		\
					      "%s:" _format_str,	\
					      ndctl_dimm_get_devname(_dimm), \
					      ##__VA_ARGS__)

/* Convert a ndctl_cmd to pdsm package */
#define to_pdsm(C)  (&(C)->papr[0].pdsm)

/* Convert a ndctl_cmd to nd_cmd_pkg */
#define to_ndcmd(C)  (&(C)->papr[0].gen)

/* Return payload from a ndctl_cmd */
#define to_payload(C) (&(C)->papr[0].pdsm.payload)

/* return the pdsm command */
#define to_pdsm_cmd(C) ((enum papr_pdsm)to_ndcmd(C)->nd_command)

static bool papr_cmd_is_supported(struct ndctl_dimm *dimm, int cmd)
{
	/* Handle this separately to support monitor mode */
	if (cmd == ND_CMD_SMART)
		return true;

	return !!(dimm->cmd_mask & (1ULL << cmd));
}

static u32 papr_get_firmware_status(struct ndctl_cmd *cmd)
{
	const struct nd_pkg_pdsm *pcmd = to_pdsm(cmd);

	return (u32) pcmd->cmd_status;
}

static int papr_xlat_firmware_status(struct ndctl_cmd *cmd)
{
	return (cmd->type == ND_CMD_CALL) ? to_pdsm(cmd)->cmd_status : 0;
}

/* Verify if the given command is supported and valid */
static bool cmd_is_valid(struct ndctl_cmd *cmd)
{
	const struct nd_cmd_pkg  *ncmd = NULL;

	if (cmd == NULL)
		return false;

	ncmd = to_ndcmd(cmd);

	/* Verify the command family */
	if (ncmd->nd_family != NVDIMM_FAMILY_PAPR) {
		papr_err(cmd->dimm, "Invalid command family:0x%016llx\n",
			 ncmd->nd_family);
		return false;
	}

	/* Verify the PDSM */
	if (ncmd->nd_command <= PAPR_PDSM_MIN ||
	    ncmd->nd_command >= PAPR_PDSM_MAX) {
		papr_err(cmd->dimm, "Invalid command :0x%016llx\n",
			 ncmd->nd_command);
		return false;
	}

	return true;
}

/* Allocate a struct ndctl_cmd for given pdsm request with payload size */
static struct ndctl_cmd *allocate_cmd(struct ndctl_dimm *dimm,
				      enum papr_pdsm pdsm_cmd,
				      size_t payload_size)
{
	struct ndctl_cmd *cmd;

	/* Verify that payload size is within acceptable range */
	if (payload_size > ND_PDSM_PAYLOAD_MAX_SIZE) {
		papr_err(dimm, "Requested payload size too large %lu bytes\n",
			 payload_size);
		return NULL;
	}

	cmd = calloc(1, sizeof(struct ndctl_cmd) + sizeof(struct nd_pkg_papr));
	if (!cmd)
		return NULL;

	ndctl_cmd_ref(cmd);
	cmd->dimm = dimm;
	cmd->type = ND_CMD_CALL;
	cmd->status = 0;
	cmd->get_firmware_status = &papr_get_firmware_status;

	/* Populate the nd_cmd_pkg contained in nd_pkg_pdsm */
	*to_ndcmd(cmd) =  (struct nd_cmd_pkg) {
		.nd_family = NVDIMM_FAMILY_PAPR,
		.nd_command = pdsm_cmd,
		.nd_size_in = 0,
		.nd_size_out = ND_PDSM_HDR_SIZE + payload_size,
		.nd_fw_size = 0,
	};
	return cmd;
}

/* Parse the nd_papr_pdsm_health and update dimm flags */
static int update_dimm_flags(struct ndctl_dimm *dimm, struct nd_papr_pdsm_health *health)
{
	/* Update the dimm flags */
	dimm->flags.f_arm = health->dimm_unarmed;
	dimm->flags.f_flush = health->dimm_bad_shutdown;
	dimm->flags.f_restore = health->dimm_bad_restore;
	dimm->flags.f_smart = (health->dimm_health != 0);

	return 0;
}

/* Validate the ndctl_cmd and return applicable flags */
static unsigned int papr_smart_get_flags(struct ndctl_cmd *cmd)
{
	struct nd_pkg_pdsm *pcmd;
	struct nd_papr_pdsm_health health;
	unsigned int flags;

	if (!cmd_is_valid(cmd))
		return 0;

	pcmd = to_pdsm(cmd);
	/* If error reported then return empty flags */
	if (pcmd->cmd_status) {
		papr_err(cmd->dimm, "PDSM(0x%x) reported error:%d\n",
			 to_pdsm_cmd(cmd), pcmd->cmd_status);
		return 0;
	}

	/*
	 * In case of nvdimm health PDSM, update dimm flags
	 * and  return possible flags.
	 */
	if (to_pdsm_cmd(cmd) == PAPR_PDSM_HEALTH) {
		health = pcmd->payload.health;
		update_dimm_flags(cmd->dimm, &health);
		flags = ND_SMART_HEALTH_VALID | ND_SMART_SHUTDOWN_VALID;

		/* check for extension flags */
		if (health.extension_flags & PDSM_DIMM_HEALTH_RUN_GAUGE_VALID)
			flags |= ND_SMART_USED_VALID;

		if (health.extension_flags & PDSM_DIMM_HEALTH_MEDIA_TEMPERATURE_VALID)
			flags |= ND_SMART_MTEMP_VALID;

		if (health.extension_flags & PDSM_DIMM_HEALTH_CTRL_TEMPERATURE_VALID)
			flags |= ND_SMART_CTEMP_VALID;

		if (health.extension_flags & PDSM_DIMM_HEALTH_SPARES_VALID)
			flags |= ND_SMART_SPARES_VALID;

		if (health.extension_flags & PDSM_DIMM_HEALTH_ALARM_VALID)
			flags |= ND_SMART_ALARM_VALID;

		return flags;
	}

	/* Else return empty flags */
	return 0;
}

static struct ndctl_cmd *papr_new_smart_health(struct ndctl_dimm *dimm)
{
	struct ndctl_cmd *cmd;

	cmd = allocate_cmd(dimm, PAPR_PDSM_HEALTH,
			       sizeof(struct nd_papr_pdsm_health));
	if (!cmd)
		papr_err(dimm, "Unable to allocate smart_health command\n");

	return cmd;
}

static unsigned int papr_smart_get_health(struct ndctl_cmd *cmd)
{
	struct nd_papr_pdsm_health health;

	/* Ignore in case of error or invalid pdsm */
	if (!cmd_is_valid(cmd) ||
	    to_pdsm(cmd)->cmd_status != 0 ||
	    to_pdsm_cmd(cmd) != PAPR_PDSM_HEALTH)
		return 0;

	/* get the payload from command */
	health = to_payload(cmd)->health;

	/* Use some math to return one of defined ND_SMART_*_HEALTH values */
	return  !health.dimm_health ? 0 : 1 << (health.dimm_health - 1);
}

static int papr_pdsm_health_set_threshold_valid(struct ndctl_cmd *cmd)
{
       if (!cmd_is_valid(cmd) ||
           to_pdsm(cmd)->cmd_status != 0 ||
           to_pdsm_cmd(cmd) != PAPR_PDSM_HEALTH_THRESHOLD_SET) {
               return -EINVAL;
       }

       return 0;
}

static unsigned int papr_cmd_smart_threshold_get_supported_alarms(
               struct ndctl_cmd *cmd)
{
       if (papr_pdsm_health_set_threshold_valid(cmd) < 0)
               return 0;
       return ND_SMART_SPARE_TRIP | ND_SMART_MTEMP_TRIP
               | ND_SMART_CTEMP_TRIP;
}

static unsigned int papr_smart_get_shutdown_state(struct ndctl_cmd *cmd)
{
	struct nd_papr_pdsm_health health;

	/* Ignore in case of error or invalid pdsm */
	if (!cmd_is_valid(cmd) ||
	    to_pdsm(cmd)->cmd_status != 0 ||
	    to_pdsm_cmd(cmd) != PAPR_PDSM_HEALTH)
		return 0;

	/* get the payload from command */
	health = to_payload(cmd)->health;

	/* return the bad shutdown flag returned from papr_scm */
	return health.dimm_bad_shutdown;
}

static int papr_smart_inject_supported(struct ndctl_dimm *dimm)
{
	struct ndctl_ctx *ctx = ndctl_dimm_get_ctx(dimm);

	if (!ndctl_dimm_is_cmd_supported(dimm, ND_CMD_CALL)) {
		dbg(ctx, "unsupported cmd: %d\n", ND_CMD_CALL);
		return -EOPNOTSUPP;
	}

	if (!test_dimm_dsm(dimm, PAPR_PDSM_HEALTH_INJECT)) {
		dbg(ctx, "smart injection functions unsupported\n");
		return -EIO;
	}

	return 0;
}

static int papr_smart_inject_valid(struct ndctl_cmd *cmd)
{
	if (cmd->type != ND_CMD_CALL ||
			to_pdsm(cmd)->cmd_status != 0 ||
			to_pdsm_cmd(cmd) != PAPR_PDSM_HEALTH_INJECT)
		return -EINVAL;

	return 0;
}

static int papr_cmd_smart_inject_media_temperature(struct ndctl_cmd *cmd,
		bool enable, unsigned int mtemp)
{
	if (papr_smart_inject_valid(cmd) < 0)
		return -EINVAL;

	to_payload(cmd)->inject.flags |= ND_PAPR_SMART_INJECT_MTEMP;
	to_payload(cmd)->inject.mtemp_enable = enable == true;
	to_payload(cmd)->inject.media_temperature = mtemp;

	return 0;
}

static int papr_cmd_smart_inject_ctrl_temperature(struct ndctl_cmd *cmd,
		bool enable, unsigned int mtemp)
{
	if (papr_smart_inject_valid(cmd) < 0)
		return -EINVAL;

	to_payload(cmd)->inject.flags |= ND_PAPR_SMART_INJECT_MTEMP;
	to_payload(cmd)->inject.ctemp_enable = enable == true;
	to_payload(cmd)->inject.ctrl_temperature = mtemp;

	return 0;
}

static int papr_cmd_smart_inject_spares(struct ndctl_cmd *cmd,
		bool enable, unsigned int spares)
{
	if (papr_smart_inject_valid(cmd) < 0)
		return -EINVAL;

	to_payload(cmd)->inject.flags |= ND_PAPR_SMART_INJECT_SPARES;
	to_payload(cmd)->inject.spares_enable = enable == true;
	to_payload(cmd)->inject.spares = spares;

	return 0;
}

static struct ndctl_cmd *papr_new_smart_inject(struct ndctl_dimm *dimm)
{
	struct ndctl_cmd *cmd;

	cmd = allocate_cmd(dimm, PAPR_PDSM_HEALTH_INJECT,
			sizeof(struct nd_papr_pdsm_health_inject));
	if (!cmd)
		return NULL;

	return cmd;
}

static struct ndctl_cmd *papr_dimm_cmd_new_smart_set_threshold(
		struct ndctl_cmd *threshold_cmd)
{
	struct ndctl_cmd *set_cmd;
	struct nd_papr_pdsm_health_threshold thresh;

	if (!cmd_is_valid(threshold_cmd) ||
	    to_pdsm(threshold_cmd)->cmd_status != 0 ||
	    to_pdsm_cmd(threshold_cmd) != PAPR_PDSM_HEALTH_THRESHOLD) {
		return NULL;
	}

	thresh = to_payload(threshold_cmd)->threshold;

	set_cmd = allocate_cmd(threshold_cmd->dimm, PAPR_PDSM_HEALTH_THRESHOLD_SET,
			sizeof(struct nd_papr_pdsm_health_threshold));
	if (!set_cmd)
		return NULL;

	set_cmd->source = threshold_cmd;
	ndctl_cmd_ref(threshold_cmd);

	to_payload(set_cmd)->threshold.alarm_control = thresh.alarm_control;
	to_payload(set_cmd)->threshold.spares = thresh.spares;
	to_payload(set_cmd)->threshold.media_temperature = thresh.media_temperature;
	to_payload(set_cmd)->threshold.ctrl_temperature = thresh.ctrl_temperature;

	return set_cmd;
}

static struct ndctl_cmd *papr_cmd_new_smart_threshold(struct ndctl_dimm *dimm)
{
	struct ndctl_cmd *cmd;

	cmd = allocate_cmd(dimm, PAPR_PDSM_HEALTH_THRESHOLD,
			sizeof(struct nd_papr_pdsm_health_threshold));
	if (!cmd)
		return NULL;

	return cmd;
}

static unsigned int papr_smart_get_life_used(struct ndctl_cmd *cmd)
{
	struct nd_papr_pdsm_health health;

	/* Ignore in case of error or invalid pdsm */
	if (!cmd_is_valid(cmd) ||
	    to_pdsm(cmd)->cmd_status != 0 ||
	    to_pdsm_cmd(cmd) != PAPR_PDSM_HEALTH)
		return 0;

	/* get the payload from command */
	health = to_payload(cmd)->health;

	/* return dimm life remaining from the health payload */
	return (health.extension_flags & PDSM_DIMM_HEALTH_RUN_GAUGE_VALID) ?
		(100 - health.dimm_fuel_gauge) : 0;
}

static int papr_cmd_smart_inject_fatal(struct ndctl_cmd *cmd, bool enable)
{
	if (papr_smart_inject_valid(cmd) < 0)
		return -EINVAL;

	to_payload(cmd)->inject.flags |= ND_PAPR_SMART_INJECT_FATAL;
	to_payload(cmd)->inject.fatal_enable = enable == true;

	return 0;
}

static int papr_cmd_smart_inject_unsafe_shutdown(struct ndctl_cmd *cmd,
							bool enable)
{
	if (papr_smart_inject_valid(cmd) < 0)
		return -EINVAL;

	to_payload(cmd)->inject.flags |= ND_PAPR_SMART_INJECT_SHUTDOWN;
	to_payload(cmd)->inject.unsafe_shutdown_enable = enable == true;

	return 0;
}

static unsigned int papr_cmd_smart_threshold_get_alarm_control(struct ndctl_cmd *cmd)
{
	int rc = 0;
	unsigned int flags = 0;
	struct nd_pkg_pdsm *pcmd = to_pdsm(cmd);
	struct nd_papr_pdsm_health_threshold threshold;

	if (!cmd_is_valid(cmd) ||
	    to_pdsm(cmd)->cmd_status != 0 ||
	    to_pdsm_cmd(cmd) != PAPR_PDSM_HEALTH_THRESHOLD) {
		rc = -EINVAL;
	}

        if (rc < 0) {
		errno = -rc;
		return UINT_MAX;
	}

	threshold = pcmd->payload.threshold;
	if (threshold.alarm_control & ND_PAPR_HEALTH_SPARE_TRIP)
		flags |= ND_SMART_SPARE_TRIP;
	if (threshold.alarm_control & ND_PAPR_HEALTH_TEMP_TRIP)
		flags |= ND_SMART_TEMP_TRIP;
	if (threshold.alarm_control & ND_PAPR_HEALTH_CTEMP_TRIP)
		flags |= ND_SMART_CTEMP_TRIP;

	return flags;
}

static int papr_smart_threshold_valid(struct ndctl_cmd *cmd)
{
	int rc = 0;

	if (!cmd_is_valid(cmd) ||
		to_pdsm(cmd)->cmd_status != 0 ||
		to_pdsm_cmd(cmd) != PAPR_PDSM_HEALTH_THRESHOLD) {
		rc = -EINVAL;
	}

	return rc;
}

#define papr_smart_threshold_get_field(cmd, field) \
static unsigned int papr_cmd_smart_threshold_get_##field( \
		struct ndctl_cmd *cmd) \
{ \
	int rc; \
	struct nd_pkg_pdsm *pcmd = to_pdsm(cmd); \
	rc = papr_smart_threshold_valid(cmd); \
	if (rc < 0) { \
		errno = -rc; \
		return UINT_MAX; \
	} \
	return pcmd->payload.threshold.field; \
}

papr_smart_threshold_get_field(cmd, media_temperature)
papr_smart_threshold_get_field(cmd, ctrl_temperature)
papr_smart_threshold_get_field(cmd, spares)

static int papr_smart_valid(struct ndctl_cmd *cmd)
{
	int rc = 0;

	if (!cmd_is_valid(cmd) ||
		to_pdsm(cmd)->cmd_status != 0 ||
		to_pdsm_cmd(cmd) != PAPR_PDSM_HEALTH) {
		rc = -EINVAL;
	}

	return rc;
}


#define papr_smart_get_field(cmd, field) \
static unsigned int papr_cmd_smart_get_##field(struct ndctl_cmd *cmd) \
{ \
	int rc; \
	struct nd_pkg_pdsm *pcmd = to_pdsm(cmd); \
	rc = papr_smart_valid(cmd); \
	if (rc < 0) { \
		errno = -rc; \
		return UINT_MAX; \
	} \
	return pcmd->payload.health.field; \
}

papr_smart_get_field(cmd, ctrl_temperature)
papr_smart_get_field(cmd, media_temperature)
papr_smart_get_field(cmd, alarm_flags)
papr_smart_get_field(cmd, spares)

#define papr_cmd_smart_threshold_set_field(field) \
static int papr_cmd_smart_threshold_set_##field( \
				struct ndctl_cmd *cmd, unsigned int val) \
{ \
	struct nd_pkg_pdsm *pcmd = to_pdsm(cmd); \
	if (papr_pdsm_health_set_threshold_valid(cmd) < 0) \
		return -EINVAL; \
	pcmd->payload.threshold.field = val; \
	return 0; \
}

papr_cmd_smart_threshold_set_field(alarm_control)
papr_cmd_smart_threshold_set_field(media_temperature)
papr_cmd_smart_threshold_set_field(ctrl_temperature)
papr_cmd_smart_threshold_set_field(spares)


struct ndctl_dimm_ops * const papr_dimm_ops = &(struct ndctl_dimm_ops) {
	.cmd_is_supported = papr_cmd_is_supported,
	.new_smart_inject = papr_new_smart_inject,
	.smart_get_flags = papr_smart_get_flags,
	.smart_inject_supported = papr_smart_inject_supported,
	.smart_inject_media_temperature = papr_cmd_smart_inject_media_temperature,
	.smart_inject_ctrl_temperature = papr_cmd_smart_inject_ctrl_temperature,
	.smart_inject_spares = papr_cmd_smart_inject_spares,
	.smart_inject_fatal = papr_cmd_smart_inject_fatal,
	.smart_inject_unsafe_shutdown = papr_cmd_smart_inject_unsafe_shutdown,
	.smart_get_ctrl_temperature = papr_cmd_smart_get_ctrl_temperature,
	.smart_get_media_temperature = papr_cmd_smart_get_media_temperature,
	.smart_get_alarm_flags = papr_cmd_smart_get_alarm_flags,
	.smart_get_spares = papr_cmd_smart_get_spares,
	.get_firmware_status =  papr_get_firmware_status,
	.xlat_firmware_status = papr_xlat_firmware_status,
	.new_smart = papr_new_smart_health,
	.smart_get_health = papr_smart_get_health,
	.smart_get_shutdown_state = papr_smart_get_shutdown_state,
	.smart_get_life_used = papr_smart_get_life_used,
	.new_smart_threshold = papr_cmd_new_smart_threshold,
	.smart_threshold_get_alarm_control
		= papr_cmd_smart_threshold_get_alarm_control,
	.smart_threshold_get_media_temperature
		= papr_cmd_smart_threshold_get_media_temperature,
	.smart_threshold_get_ctrl_temperature
		= papr_cmd_smart_threshold_get_ctrl_temperature,
	.smart_threshold_get_spares = papr_cmd_smart_threshold_get_spares,
	.new_smart_set_threshold = papr_dimm_cmd_new_smart_set_threshold,
	.smart_threshold_get_supported_alarms
		= papr_cmd_smart_threshold_get_supported_alarms,
	.smart_threshold_set_alarm_control
		= papr_cmd_smart_threshold_set_alarm_control,
	.smart_threshold_set_media_temperature
		= papr_cmd_smart_threshold_set_media_temperature,
	.smart_threshold_set_ctrl_temperature
		= papr_cmd_smart_threshold_set_ctrl_temperature,
	.smart_threshold_set_spares = papr_cmd_smart_threshold_set_spares,
};
