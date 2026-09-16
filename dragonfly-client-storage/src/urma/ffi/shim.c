/*
 * Copyright 2026 The Dragonfly Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define _POSIX_C_SOURCE 200112L

#include "shim.h"

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <urma_api.h>

_Static_assert(URMA_CR_OPC_SEND == 0,
               "URMA SEND completion opcode changed");
_Static_assert(URMA_CR_OPC_SEND_WITH_IMM == DFURMA_CR_OPC_SEND_WITH_IMM,
               "URMA SEND_WITH_IMM completion opcode changed");
_Static_assert(sizeof(((urma_eid_t *)0)->raw) == DFURMA_EID_SIZE,
               "URMA EID size changed");
_Static_assert(URMA_RTP == DFURMA_TP_RTP, "URMA RTP value changed");
_Static_assert(URMA_CTP == DFURMA_TP_CTP, "URMA CTP value changed");
_Static_assert(URMA_ACCESS_READ == DFURMA_READ_ACCESS, "URMA READ access changed");
_Static_assert(URMA_TOKEN_PLAIN_TEXT == DFURMA_READ_TOKEN_PLAIN, "URMA token policy changed");

struct dfurma_runtime {
    urma_device_t *device;
    urma_context_t *context;
    uint32_t eid_index;
    uint32_t jfc_count;
    uint32_t segment_count;
    uint32_t jetty_count;
    uint32_t outstanding_wr_count;
};

struct dfurma_jfc {
    dfurma_runtime_t *runtime;
    urma_jfc_t *jfc;
};

struct dfurma_segment {
    dfurma_runtime_t *runtime;
    urma_target_seg_t *segment;
    void *memory;
    uint64_t length;
    uint32_t outstanding_wr_count;
};

struct dfurma_jetty {
    dfurma_runtime_t *runtime;
    urma_jfr_t *jfr;
    urma_jetty_t *jetty;
    int jetty_error;
    int jfr_error;
    uint32_t outstanding_wr_count;
    uint32_t target_count;
    dfurma_wr_t *wr_arena;
    dfurma_wr_t *free_wr;
    uint32_t wr_capacity;
    urma_tp_type_t tp_type;
    uint8_t priority;
};

struct dfurma_target {
    dfurma_jetty_t *jetty;
    urma_target_jetty_t *target;
    uint32_t outstanding_wr_count;
    uint32_t read_segment_count;
};

struct dfurma_read_segment {
    dfurma_target_t *target;
    urma_target_seg_t *segment;
    uint64_t va;
    uint64_t length;
    uint32_t max_read_size;
    uint32_t outstanding_wr_count;
};

struct dfurma_read_source {
    dfurma_runtime_t *runtime;
    urma_target_seg_t *segment;
    urma_token_id_t *token_id;
    uint64_t va;
    uint64_t length;
    int closing;
    int registration_uncertain;
};

struct dfurma_wr {
    dfurma_runtime_t *runtime;
    dfurma_segment_t *segment;
    dfurma_jetty_t *jetty;
    dfurma_target_t *target;
    dfurma_read_segment_t *read_segment;
    urma_sge_t remote_sge;
    urma_sge_t sge;
    urma_jfs_wr_t send_wr;
    urma_jfr_wr_t recv_wr;
    dfurma_wr_t *next_free;
};

static int dfurma_pointer_error(int fallback)
{
    return errno > 0 ? -errno : fallback;
}

/*
 * Match urma_perftest's provider-facing priority selection.  On current UB
 * devices the selected TP type determines the service-class priority.
 * URMA_MAX_PRIORITY is only the largest valid numeric value; it does not mean
 * "fastest" and may select a different, rate-limited TP class.
 */
static int dfurma_get_tp_priority(dfurma_runtime_t *runtime,
                                  urma_tp_type_t tp_type,
                                  uint8_t *priority)
{
    urma_device_attr_t attr = {0};
    union urma_tp_type_en requested = {0};
    urma_status_t status;

    if (runtime == NULL || runtime->device == NULL ||
        runtime->context == NULL || priority == NULL) {
        return -EINVAL;
    }

    /* The public API does not expose provider ops. Non-UB transports retain
     * the legacy priority used by perftest when extended import is absent. */
    if (runtime->device->type != URMA_TRANSPORT_UB) {
        *priority = 0;
        return 0;
    }

    status = urma_query_device(runtime->device, &attr);
    if (status != URMA_SUCCESS) {
        return (int)status;
    }
    if (tp_type == URMA_RTP) {
        requested.bs.rtp = 1;
    } else if (tp_type == URMA_CTP) {
        requested.bs.ctp = 1;
    } else {
        return -EINVAL;
    }
    for (uint8_t i = 0; i <= URMA_MAX_PRIORITY; ++i) {
        if (attr.dev_cap.priority_info[i].tp_type.value == requested.value) {
            *priority = i;
            return 0;
        }
    }
    return -ENOTSUP;
}

int dfurma_runtime_open(const char *device_name, uint32_t eid_index,
                          dfurma_runtime_t **out)
{
    dfurma_runtime_t *runtime;
    urma_status_t status;

    if (device_name == NULL || out == NULL) {
        return -EINVAL;
    }
    *out = NULL;

    status = urma_init(NULL);
    if (status != URMA_SUCCESS) {
        return (int)status;
    }

    runtime = calloc(1, sizeof(*runtime));
    if (runtime == NULL) {
        (void)urma_uninit();
        return -ENOMEM;
    }

    /* liburma currently declares this input as char *, but does not own it. */
    runtime->device = urma_get_device_by_name((char *)device_name);
    if (runtime->device == NULL) {
        free(runtime);
        (void)urma_uninit();
        return -ENODEV;
    }

    runtime->context = urma_create_context(runtime->device, eid_index);
    if (runtime->context == NULL) {
        free(runtime);
        (void)urma_uninit();
        return -EIO;
    }

    runtime->eid_index = eid_index;
    *out = runtime;
    return 0;
}

int dfurma_runtime_query_device(dfurma_runtime_t *runtime,
                                  dfurma_device_capability_t *out)
{
    urma_device_attr_t attr = {0};
    urma_status_t status;

    if (runtime == NULL || runtime->device == NULL || out == NULL) {
        return -EINVAL;
    }
    status = urma_query_device(runtime->device, &attr);
    if (status != URMA_SUCCESS) {
        return (int)status;
    }

    (void)memset(out, 0, sizeof(*out));
    out->transport_type = (int32_t)runtime->device->type;
    out->transport_modes = attr.dev_cap.trans_mode;
    out->max_jfc = attr.dev_cap.max_jfc;
    out->max_jfs = attr.dev_cap.max_jfs;
    out->max_jfr = attr.dev_cap.max_jfr;
    out->max_jetty = attr.dev_cap.max_jetty;
    out->max_jfc_depth = attr.dev_cap.max_jfc_depth;
    out->max_jfs_depth = attr.dev_cap.max_jfs_depth;
    out->max_jfr_depth = attr.dev_cap.max_jfr_depth;
    out->max_jfs_sge = attr.dev_cap.max_jfs_sge;
    out->max_jfs_rsge = attr.dev_cap.max_jfs_rsge;
    out->max_jfr_sge = attr.dev_cap.max_jfr_sge;
    out->max_msg_size = attr.dev_cap.max_msg_size;
    out->max_read_size = attr.dev_cap.max_read_size;
    out->max_write_size = attr.dev_cap.max_write_size;
    return 0;
}

int dfurma_jfc_create(dfurma_runtime_t *runtime, uint32_t depth,
                        dfurma_jfc_t **out)
{
    urma_jfc_cfg_t cfg = {0};
    dfurma_jfc_t *jfc;

    if (runtime == NULL || runtime->context == NULL || out == NULL || depth == 0) {
        return -EINVAL;
    }
    *out = NULL;

    jfc = calloc(1, sizeof(*jfc));
    if (jfc == NULL) {
        return -ENOMEM;
    }
    cfg.depth = depth;
    cfg.jfce = NULL;
    errno = 0;
    jfc->jfc = urma_create_jfc(runtime->context, &cfg);
    if (jfc->jfc == NULL) {
        int error = dfurma_pointer_error(-EIO);
        free(jfc);
        return error;
    }

    jfc->runtime = runtime;
    runtime->jfc_count++;
    *out = jfc;
    return 0;
}

int dfurma_jfc_delete(dfurma_jfc_t *jfc)
{
    urma_status_t status;
    dfurma_runtime_t *runtime;

    if (jfc == NULL || jfc->jfc == NULL || jfc->runtime == NULL) {
        return -EINVAL;
    }
    runtime = jfc->runtime;
    if (runtime->outstanding_wr_count != 0) {
        return -EBUSY;
    }
    status = urma_delete_jfc(jfc->jfc);
    if (status != URMA_SUCCESS) {
        return (int)status;
    }
    if (runtime->jfc_count > 0) {
        runtime->jfc_count--;
    }
    jfc->jfc = NULL;
    free(jfc);
    return 0;
}

static int dfurma_segment_create_impl(dfurma_runtime_t *runtime, uint64_t length,
                            uint64_t alignment, dfurma_segment_t **out, int retain_failure)
{
    urma_seg_cfg_t cfg = {0};
    dfurma_segment_t *segment;
    int alloc_status;

    if (runtime == NULL || runtime->context == NULL || out == NULL || length == 0 ||
        length > SIZE_MAX || alignment < sizeof(void *) || alignment > SIZE_MAX ||
        (alignment & (alignment - 1)) != 0) {
        return -EINVAL;
    }
    *out = NULL;

    segment = calloc(1, sizeof(*segment));
    if (segment == NULL) {
        return -ENOMEM;
    }
    alloc_status = posix_memalign(&segment->memory, (size_t)alignment, (size_t)length);
    if (alloc_status != 0) {
        free(segment);
        return -alloc_status;
    }
    (void)memset(segment->memory, 0, (size_t)length);

    /*
     * Confirm page/alignment and pinning behavior on every supported provider.
     * Dragonfly requests only local access for the two-sided data path.
     */
    cfg.va = (uint64_t)(uintptr_t)segment->memory;
    cfg.len = length;
    cfg.flag.value = 0;
    cfg.flag.bs.token_policy = URMA_TOKEN_NONE;
    cfg.flag.bs.cacheable = URMA_NON_CACHEABLE;
    cfg.flag.bs.access = URMA_ACCESS_LOCAL_ONLY;
    cfg.flag.bs.token_id_valid = URMA_TOKEN_ID_INVALID;
    errno = 0;
    segment->segment = urma_register_seg(runtime->context, &cfg);
    if (segment->segment == NULL) {
        int error = dfurma_pointer_error(-EIO);
        if (retain_failure) {
            /* No proof that failed registration rolled back all pinning. */
            segment->runtime = runtime;
            segment->length = length;
            runtime->segment_count++;
            *out = segment;
            return error;
        }
        free(segment->memory);
        free(segment);
        return error;
    }

    segment->runtime = runtime;
    segment->length = length;
    runtime->segment_count++;
    *out = segment;
    return 0;
}

int dfurma_segment_create(dfurma_runtime_t *runtime, uint64_t length,
                            uint64_t alignment, dfurma_segment_t **out)
{
    return dfurma_segment_create_impl(runtime, length, alignment, out, 0);
}

int dfurma_read_buffer_create(dfurma_runtime_t *runtime, uint64_t length,
                            uint64_t alignment, dfurma_segment_t **out)
{
    return dfurma_segment_create_impl(runtime, length, alignment, out, 1);
}

int dfurma_segment_delete(dfurma_segment_t *segment)
{
    urma_status_t status;
    dfurma_runtime_t *runtime;

    if (segment == NULL || segment->segment == NULL || segment->runtime == NULL) {
        return -EINVAL;
    }
    if (segment->outstanding_wr_count != 0) {
        return -EBUSY;
    }
    runtime = segment->runtime;
    status = urma_unregister_seg(segment->segment);
    if (status != URMA_SUCCESS) {
        /* Keep both registered handle and backing memory alive on failure. */
        return (int)status;
    }
    if (runtime->segment_count > 0) {
        runtime->segment_count--;
    }
    segment->segment = NULL;
    free(segment->memory);
    segment->memory = NULL;
    free(segment);
    return 0;
}

static int dfurma_segment_range(const dfurma_segment_t *segment,
                                  uint64_t offset, uint32_t length)
{
    if (segment == NULL || segment->segment == NULL || segment->memory == NULL ||
        length == 0 || offset > segment->length ||
        (uint64_t)length > segment->length - offset) {
        return -EINVAL;
    }
    return 0;
}

int dfurma_segment_data(dfurma_segment_t *segment, uint8_t **data,
                          uint64_t *length)
{
    if (segment == NULL || segment->segment == NULL ||
        segment->memory == NULL || data == NULL || length == NULL) {
        return -EINVAL;
    }
    *data = (uint8_t *)segment->memory;
    *length = segment->length;
    return 0;
}

int dfurma_jetty_create(dfurma_runtime_t *runtime,
                          dfurma_jfc_t *send_jfc,
                          dfurma_jfc_t *recv_jfc,
                          const dfurma_jetty_config_t *config,
                          dfurma_jetty_t **out)
{
    urma_jfs_cfg_t jfs_cfg = {0};
    urma_jfr_cfg_t jfr_cfg = {0};
    urma_jetty_cfg_t jetty_cfg = {0};
    dfurma_jetty_t *jetty;
    uint8_t tp_priority;
    urma_tp_type_t tp_type;
    int priority_status;

    if (runtime == NULL || runtime->context == NULL || send_jfc == NULL ||
        recv_jfc == NULL || config == NULL || out == NULL ||
        send_jfc->runtime != runtime || recv_jfc->runtime != runtime ||
        send_jfc->jfc == NULL || recv_jfc->jfc == NULL ||
        config->send_depth == 0 || config->recv_depth == 0 ||
        config->max_send_sge == 0 || config->max_send_sge > UINT8_MAX ||
        config->max_recv_sge == 0 || config->max_recv_sge > UINT8_MAX ||
        (config->tp_type != DFURMA_TP_RTP &&
         config->tp_type != DFURMA_TP_CTP)) {
        return -EINVAL;
    }
    *out = NULL;

    tp_type = (urma_tp_type_t)config->tp_type;
    if (tp_type == URMA_CTP && runtime->device->type != URMA_TRANSPORT_UB) {
        return -ENOTSUP;
    }
    priority_status = dfurma_get_tp_priority(runtime, tp_type, &tp_priority);
    if (priority_status != 0) {
        return priority_status;
    }

    jetty = calloc(1, sizeof(*jetty));
    if (jetty == NULL) {
        return -ENOMEM;
    }
    if (config->send_depth > UINT32_MAX - config->recv_depth) {
        free(jetty);
        return -EOVERFLOW;
    }
    jetty->wr_capacity = config->send_depth + config->recv_depth;
    jetty->wr_arena = calloc(jetty->wr_capacity, sizeof(*jetty->wr_arena));
    if (jetty->wr_arena == NULL) {
        free(jetty);
        return -ENOMEM;
    }
    for (uint32_t i = 0; i < jetty->wr_capacity; ++i) {
        jetty->wr_arena[i].next_free = jetty->free_wr;
        jetty->free_wr = &jetty->wr_arena[i];
    }

    jfs_cfg.depth = config->send_depth;
    jfs_cfg.trans_mode = URMA_TM_RM;
    jfs_cfg.priority = tp_priority;
    jfs_cfg.max_sge = (uint8_t)config->max_send_sge;
    jfs_cfg.max_rsge = 1;
    jfs_cfg.max_inline_data = 0;
    jfs_cfg.rnr_retry = URMA_TYPICAL_RNR_RETRY;
    jfs_cfg.err_timeout = URMA_TYPICAL_ERR_TIMEOUT;
    jfs_cfg.jfc = send_jfc->jfc;

    jfr_cfg.depth = config->recv_depth;
    jfr_cfg.flag.value = 0;
    jfr_cfg.flag.bs.tag_matching = URMA_NO_TAG_MATCHING;
    jfr_cfg.trans_mode = URMA_TM_RM;
    jfr_cfg.max_sge = (uint8_t)config->max_recv_sge;
    jfr_cfg.min_rnr_timer = URMA_TYPICAL_MIN_RNR_TIMER;
    jfr_cfg.jfc = recv_jfc->jfc;
    jfr_cfg.token_value.token = config->token;

    errno = 0;
    jetty->jfr = urma_create_jfr(runtime->context, &jfr_cfg);
    if (jetty->jfr == NULL) {
        int error = dfurma_pointer_error(-EIO);
        free(jetty->wr_arena);
        free(jetty);
        return error;
    }

    jetty_cfg.flag.value = 0;
    jetty_cfg.flag.bs.share_jfr = URMA_SHARE_JFR;
    jetty_cfg.jfs_cfg = jfs_cfg;
    jetty_cfg.shared.jfr = jetty->jfr;
    jetty_cfg.shared.jfc = recv_jfc->jfc;

    errno = 0;
    jetty->jetty = urma_create_jetty(runtime->context, &jetty_cfg);
    if (jetty->jetty == NULL) {
        int error = dfurma_pointer_error(-EIO);
        (void)urma_delete_jfr(jetty->jfr);
        jetty->jfr = NULL;
        free(jetty->wr_arena);
        free(jetty);
        return error;
    }

    jetty->runtime = runtime;
    jetty->tp_type = tp_type;
    jetty->priority = tp_priority;
    runtime->jetty_count++;
    *out = jetty;
    return 0;
}

int dfurma_jetty_mark_error(dfurma_jetty_t *jetty)
{
    urma_jetty_attr_t attr = {0};
    urma_jfr_attr_t jfr_attr = {0};
    urma_status_t status;
    int first_error = 0;

    if (jetty == NULL || jetty->jetty == NULL || jetty->jfr == NULL) {
        return -EINVAL;
    }
    if (jetty->jetty_error == 0) {
        attr.mask = JETTY_STATE;
        attr.state = URMA_JETTY_STATE_ERROR;
        status = urma_modify_jetty(jetty->jetty, &attr);
        if (status == URMA_SUCCESS) {
            jetty->jetty_error = 1;
        } else {
            first_error = (int)status;
        }
    }
    /* The Jetty was created with an independently owned shared JFR. Moving
     * only the Jetty to ERROR does not flush receive WRs on that JFR. */
    if (jetty->jfr_error == 0) {
        jfr_attr.mask = JFR_STATE;
        jfr_attr.state = URMA_JFR_STATE_ERROR;
        status = urma_modify_jfr(jetty->jfr, &jfr_attr);
        if (status == URMA_SUCCESS) {
            jetty->jfr_error = 1;
        } else if (first_error == 0) {
            first_error = (int)status;
        }
    }
    return first_error;
}

int dfurma_jetty_local_ids(dfurma_jetty_t *jetty,
                             uint32_t *jetty_id, uint32_t *jfr_id)
{
    if (jetty == NULL || jetty->jetty == NULL || jetty->jfr == NULL ||
        jetty_id == NULL || jfr_id == NULL) {
        return -EINVAL;
    }
    *jetty_id = jetty->jetty->jetty_id.id;
    *jfr_id = jetty->jfr->jfr_id.id;
    return 0;
}

int dfurma_jetty_export_descriptor(dfurma_jetty_t *jetty,
                                     dfurma_jetty_descriptor_meta_t *meta,
                                     uint8_t **opaque_data)
{
    urma_rjetty_t *rjetty = NULL;
    uint32_t length = 0;
    urma_status_t status;

    if (jetty == NULL || jetty->jetty == NULL || meta == NULL ||
        opaque_data == NULL) {
        return -EINVAL;
    }
    *opaque_data = NULL;

    /* The public API requires the shared JFR owned by this Jetty wrapper. */
    status = urma_get_rjetty(jetty->jetty, &rjetty, &length);
    if (status != URMA_SUCCESS) {
        return (int)status;
    }
    if (rjetty == NULL || length < sizeof(urma_rjetty_t)) {
        urma_put_rjetty(rjetty);
        return -EPROTO;
    }

    *meta = (dfurma_jetty_descriptor_meta_t) {
        .transport_type = (uint32_t)jetty->runtime->device->type,
        .tp_type = (uint32_t)jetty->tp_type,
        .eid_index = jetty->runtime->eid_index,
        .jetty_id = rjetty->jetty_id.id,
        .opaque_len = length,
    };
    *opaque_data = (uint8_t *)rjetty;
    return 0;
}

void dfurma_descriptor_free(uint8_t *opaque_data)
{
    if (opaque_data != NULL) {
        urma_put_rjetty((urma_rjetty_t *)opaque_data);
    }
}

int dfurma_jetty_import(dfurma_jetty_t *jetty,
                          const dfurma_jetty_descriptor_meta_t *meta,
                          const uint8_t *opaque_data, uint32_t opaque_len,
                          uint32_t token, dfurma_target_t **out)
{
    urma_rjetty_t *rjetty;
    dfurma_target_t *target;
    urma_token_t token_value = {0};

    if (jetty == NULL || jetty->runtime == NULL || jetty->jetty == NULL ||
        meta == NULL || opaque_data == NULL || opaque_len == 0 ||
        opaque_len != meta->opaque_len || opaque_len < sizeof(urma_rjetty_t) ||
        out == NULL ||
        meta->transport_type != (uint32_t)jetty->runtime->device->type ||
        meta->tp_type != (uint32_t)jetty->tp_type) {
        return -EINVAL;
    }
    *out = NULL;

    rjetty = malloc(opaque_len);
    if (rjetty == NULL) {
        return -ENOMEM;
    }
    (void)memcpy(rjetty, opaque_data, opaque_len);
    if (rjetty->jetty_id.id != meta->jetty_id ||
        rjetty->trans_mode != URMA_TM_RM ||
        rjetty->type != URMA_JETTY) {
        free(rjetty);
        return -EPROTO;
    }

    /* urma_perftest applies the locally selected TP type to the imported
     * descriptor. Capability negotiation guarantees that the peer selected
     * the same value before this provider-facing override. */
    rjetty->tp_type = jetty->tp_type;

    target = calloc(1, sizeof(*target));
    if (target == NULL) {
        free(rjetty);
        return -ENOMEM;
    }

    token_value.token = token;
    errno = 0;
    target->target = urma_import_jetty(jetty->runtime->context, rjetty,
                                       &token_value);
    free(rjetty);
    if (target->target == NULL) {
        int status = dfurma_pointer_error(-EIO);
        free(target);
        return status;
    }
    target->jetty = jetty;
    jetty->target_count++;
    *out = target;
    return 0;
}

int dfurma_target_unimport(dfurma_target_t *target)
{
    urma_status_t status;
    dfurma_jetty_t *jetty;

    if (target == NULL || target->jetty == NULL || target->target == NULL) {
        return -EINVAL;
    }
    if (target->outstanding_wr_count != 0 || target->read_segment_count != 0) {
        return -EBUSY;
    }
    status = urma_unimport_jetty(target->target);
    if (status != URMA_SUCCESS) {
        return (int)status;
    }
    jetty = target->jetty;
    if (jetty->target_count > 0) {
        jetty->target_count--;
    }
    target->target = NULL;
    target->jetty = NULL;
    free(target);
    return 0;
}

int dfurma_target_remote_id(dfurma_target_t *target,
                            uint8_t eid[DFURMA_EID_SIZE], uint32_t *uasid,
                            uint32_t *jetty_id)
{
    if (target == NULL || target->target == NULL || eid == NULL ||
        uasid == NULL || jetty_id == NULL) {
        return -EINVAL;
    }
    (void)memcpy(eid, target->target->id.eid.raw, DFURMA_EID_SIZE);
    *uasid = target->target->id.uasid;
    *jetty_id = target->target->id.id;
    return 0;
}

int dfurma_jetty_delete(dfurma_jetty_t *jetty)
{
    urma_status_t status;
    dfurma_runtime_t *runtime;

    if (jetty == NULL || jetty->runtime == NULL ||
        (jetty->jetty == NULL && jetty->jfr == NULL)) {
        return -EINVAL;
    }
    if (jetty->target_count != 0 || jetty->outstanding_wr_count != 0) {
        return -EBUSY;
    }
    runtime = jetty->runtime;
    if (jetty->jetty != NULL) {
        status = urma_delete_jetty(jetty->jetty);
        if (status != URMA_SUCCESS) {
            return (int)status;
        }
        jetty->jetty = NULL;
    }
    if (jetty->jfr != NULL) {
        status = urma_delete_jfr(jetty->jfr);
        if (status != URMA_SUCCESS) {
            return (int)status;
        }
        jetty->jfr = NULL;
    }
    if (runtime->jetty_count > 0) {
        runtime->jetty_count--;
    }
    free(jetty->wr_arena);
    jetty->wr_arena = NULL;
    jetty->free_wr = NULL;
    free(jetty);
    return 0;
}

static int dfurma_wr_acquire(dfurma_jetty_t *jetty,
                               dfurma_segment_t *segment, uint64_t offset,
                               uint32_t length, dfurma_wr_t **out)
{
    dfurma_wr_t *wr;

    if (jetty == NULL || jetty->runtime == NULL || jetty->jetty == NULL ||
        segment == NULL || segment->runtime != jetty->runtime || out == NULL ||
        dfurma_segment_range(segment, offset, length) != 0) {
        return -EINVAL;
    }
    *out = NULL;
    wr = jetty->free_wr;
    if (wr == NULL) {
        return -ENOMEM;
    }
    jetty->free_wr = wr->next_free;
    (void)memset(wr, 0, sizeof(*wr));
    wr->runtime = jetty->runtime;
    wr->segment = segment;
    wr->jetty = jetty;
    wr->sge.addr = (uint64_t)(uintptr_t)((uint8_t *)segment->memory + offset);
    wr->sge.len = length;
    wr->sge.tseg = segment->segment;
    wr->sge.user_tseg = NULL;
    *out = wr;
    return 0;
}

static void dfurma_wr_return(dfurma_wr_t *wr)
{
    dfurma_jetty_t *jetty = wr->jetty;

    (void)memset(wr, 0, sizeof(*wr));
    wr->next_free = jetty->free_wr;
    jetty->free_wr = wr;
}

static void dfurma_wr_posted(dfurma_wr_t *wr)
{
    wr->runtime->outstanding_wr_count++;
    wr->segment->outstanding_wr_count++;
    wr->jetty->outstanding_wr_count++;
    if (wr->target != NULL) {
        wr->target->outstanding_wr_count++;
    }
    if (wr->read_segment != NULL) {
        wr->read_segment->outstanding_wr_count++;
    }
}

int dfurma_read_source_register(dfurma_runtime_t *runtime, const uint8_t *data,
                                uint64_t length, uint32_t token,
                                dfurma_read_source_t **out)
{
    dfurma_read_source_t *source;
    urma_seg_cfg_t cfg = {0};
    uint64_t va = (uint64_t)(uintptr_t)data;
    int error;

    if (out == NULL) {
        return -EINVAL;
    }
    *out = NULL;
    if (runtime == NULL || runtime->context == NULL || data == NULL ||
        length == 0 || length > PTRDIFF_MAX || length > UINT64_MAX - va) {
        return -EINVAL;
    }
    if (runtime->segment_count == UINT32_MAX) {
        return -EOVERFLOW;
    }
    source = calloc(1, sizeof(*source));
    if (source == NULL) {
        return -ENOMEM;
    }
    /* Own the token ID explicitly. The current core unregister path may attempt
     * to free automatically allocated IDs even on unregister failure. */
    errno = 0;
    source->token_id = urma_alloc_token_id(runtime->context);
    if (source->token_id == NULL) {
        error = dfurma_pointer_error(-EIO);
        free(source);
        return error;
    }
    source->runtime = runtime;
    source->va = va;
    source->length = length;
    runtime->segment_count++;
    cfg.va = va;
    cfg.len = length;
    cfg.token_id = source->token_id;
    cfg.token_value.token = token;
    cfg.flag.bs.token_policy = URMA_TOKEN_PLAIN_TEXT;
    cfg.flag.bs.access = URMA_ACCESS_READ;
    cfg.flag.bs.cacheable = URMA_NON_CACHEABLE;
    cfg.flag.bs.token_id_valid = URMA_TOKEN_ID_VALID;
    /* non_pin remains zero: external pages must be pinned. */
    errno = 0;
    source->segment = urma_register_seg(runtime->context, &cfg);
    error = source->segment == NULL ? dfurma_pointer_error(-EIO) : 0;
    cfg.token_value.token = 0;
    *out = source;
    if (error != 0) {
        /* Provider rollback may have failed after creating a grant. No native
         * registration handle exists to retry unregister; retain backing/token. */
        source->registration_uncertain = 1;
        source->closing = 1;
    }
    return error;
}

int dfurma_read_source_descriptor(dfurma_read_source_t *source,
                                  dfurma_read_descriptor_t *out)
{
    urma_seg_t *seg = NULL;
    urma_seg_attr_t supported = {0};
    uint32_t size = 0;
    urma_status_t status;
    int result = 0;

    if (out == NULL) {
        return -EINVAL;
    }
    memset(out, 0, sizeof(*out));
    if (source == NULL || source->segment == NULL || source->closing) {
        return -ESHUTDOWN;
    }
    status = urma_get_seg_ctx(source->segment, &seg, &size);
    if (status != URMA_SUCCESS) {
        return (int)status;
    }
    supported.bs.access = URMA_ACCESS_READ;
    supported.bs.token_policy = URMA_TOKEN_PLAIN_TEXT;
    supported.bs.cacheable = URMA_NON_CACHEABLE;
    supported.bs.user_token_id = URMA_TOKEN_ID_VALID;
    /* Reject extensions and any attribute not represented by descriptor v1. */
    if (seg == NULL || size != sizeof(*seg) || seg->attr.value != supported.value) {
        result = -EOPNOTSUPP;
    } else if (seg->ubva.va != source->va || seg->len != source->length ||
               seg->ubva.uasid > 0xffffffU) {
        result = -ERANGE;
    } else {
        out->version = DFURMA_READ_DESCRIPTOR_VERSION;
        memcpy(out->eid, seg->ubva.eid.raw, DFURMA_EID_SIZE);
        out->uasid = seg->ubva.uasid;
        out->va = seg->ubva.va;
        out->length = seg->len;
        out->token_id = seg->token_id;
        out->access = DFURMA_READ_ACCESS;
        out->token_policy = DFURMA_READ_TOKEN_PLAIN;
    }
    if (seg != NULL) {
        urma_put_seg_ctx(seg);
    }
    return result;
}

int dfurma_read_source_unregister(dfurma_read_source_t *source)
{
    urma_status_t status;

    if (source == NULL) {
        return -EINVAL;
    }
    source->closing = 1;
    if (source->registration_uncertain) {
        return -EUCLEAN;
    }
    if (source->segment == NULL) {
        return 0;
    }
    status = urma_unregister_seg(source->segment);
    if (status != URMA_SUCCESS) {
        return (int)status;
    }
    source->segment = NULL;
    /* Native unregister success does not prove ummu_ungrant succeeded. */
    return 0;
}

int dfurma_read_source_release_after_revoke(dfurma_read_source_t *source)
{
    urma_status_t status;

    if (source == NULL || source->runtime == NULL || source->token_id == NULL) {
        return -EINVAL;
    }
    if (source->segment != NULL) {
        return -EBUSY;
    }
    /* This is a caller-supplied proof boundary, NOT a probe of remote access. */
    status = urma_free_token_id(source->token_id);
    if (status != URMA_SUCCESS) {
        return (int)status;
    }
    source->runtime->segment_count--;
    source->token_id = NULL;
    free(source);
    return 0;
}

int dfurma_read_segment_import(dfurma_target_t *target,
                               const dfurma_read_descriptor_t *descriptor,
                               uint32_t token, uint32_t max_read_size,
                               dfurma_read_segment_t **out)
{
    urma_seg_t seg = {0};
    urma_import_seg_flag_t flag = {0};
    urma_token_t token_value = {.token = token};
    dfurma_device_capability_t capability;
    dfurma_read_segment_t *remote;
    dfurma_runtime_t *runtime;
    int status;

    if (out == NULL) {
        return -EINVAL;
    }
    *out = NULL;
    if (target == NULL || target->target == NULL || target->jetty == NULL ||
        target->jetty->runtime == NULL || descriptor == NULL ||
        descriptor->version != DFURMA_READ_DESCRIPTOR_VERSION ||
        descriptor->access != DFURMA_READ_ACCESS ||
        descriptor->token_policy != DFURMA_READ_TOKEN_PLAIN ||
        descriptor->uasid > 0xffffffU || descriptor->va == 0 ||
        descriptor->length == 0 || descriptor->length > UINT64_MAX - descriptor->va ||
        max_read_size == 0) {
        return -EINVAL;
    }
    /* This prototype deliberately rejects cross-context source Segments. */
    if (memcmp(descriptor->eid, target->target->id.eid.raw, DFURMA_EID_SIZE) != 0 ||
        descriptor->uasid != target->target->id.uasid) {
        return -EACCES;
    }
    runtime = target->jetty->runtime;
    status = dfurma_runtime_query_device(runtime, &capability);
    if (status != 0) {
        return status;
    }
    if ((capability.transport_modes & URMA_TM_RM) == 0 || capability.max_read_size == 0 ||
        capability.max_jfs_sge == 0 || capability.max_jfs_rsge == 0) {
        return -EOPNOTSUPP;
    }
    remote = calloc(1, sizeof(*remote));
    if (remote == NULL) {
        return -ENOMEM;
    }
    memcpy(seg.ubva.eid.raw, descriptor->eid, DFURMA_EID_SIZE);
    seg.ubva.uasid = descriptor->uasid;
    seg.ubva.va = descriptor->va;
    seg.len = descriptor->length;
    seg.token_id = descriptor->token_id;
    seg.attr.bs.access = URMA_ACCESS_READ;
    seg.attr.bs.token_policy = URMA_TOKEN_PLAIN_TEXT;
    seg.attr.bs.cacheable = URMA_NON_CACHEABLE;
    flag.bs.access = URMA_ACCESS_READ;
    flag.bs.mapping = URMA_SEG_NOMAP;
    errno = 0;
    remote->segment = urma_import_seg(runtime->context, &seg, &token_value, 0, flag);
    token_value.token = 0;
    if (remote->segment == NULL) {
        status = dfurma_pointer_error(-EIO);
        free(remote);
        return status;
    }
    remote->target = target;
    remote->va = descriptor->va;
    remote->length = descriptor->length;
    remote->max_read_size = max_read_size < capability.max_read_size ?
        max_read_size : capability.max_read_size;
    target->read_segment_count++;
    runtime->segment_count++;
    *out = remote;
    return 0;
}

int dfurma_read_segment_unimport(dfurma_read_segment_t *remote)
{
    urma_status_t status;

    if (remote == NULL || remote->segment == NULL || remote->target == NULL) {
        return -EINVAL;
    }
    if (remote->outstanding_wr_count != 0) {
        return -EBUSY;
    }
    status = urma_unimport_seg(remote->segment);
    if (status != URMA_SUCCESS) {
        return (int)status;
    }
    remote->target->read_segment_count--;
    remote->target->jetty->runtime->segment_count--;
    remote->segment = NULL;
    free(remote);
    return 0;
}

int dfurma_post_read(dfurma_jetty_t *jetty, dfurma_target_t *target,
                     dfurma_segment_t *local, dfurma_read_segment_t *remote,
                     uint64_t local_offset, uint64_t remote_offset,
                     uint32_t length, uint64_t user_ctx, dfurma_wr_t **out)
{
    dfurma_wr_t *wr;
    urma_jfs_wr_t *bad_wr = NULL;
    urma_status_t status;
    int result;

    if (out == NULL) {
        return -EINVAL;
    }
    *out = NULL;
    if (jetty == NULL || target == NULL || target->target == NULL || target->jetty != jetty ||
        remote == NULL || remote->segment == NULL || remote->target != target ||
        length == 0 || length > remote->max_read_size || remote_offset > remote->length ||
        (uint64_t)length > remote->length - remote_offset) {
        return -EINVAL;
    }
    if (jetty->jetty_error || jetty->jfr_error) {
        return -ESHUTDOWN;
    }
    result = dfurma_wr_acquire(jetty, local, local_offset, length, &wr);
    if (result != 0) {
        return result;
    }
    wr->target = target;
    wr->read_segment = remote;
    wr->remote_sge.addr = remote->va + remote_offset;
    wr->remote_sge.len = length;
    wr->remote_sge.tseg = remote->segment;
    wr->send_wr.opcode = URMA_OPC_READ;
    wr->send_wr.flag.bs.complete_enable = 1;
    wr->send_wr.tjetty = target->target;
    wr->send_wr.user_ctx = user_ctx;
    wr->send_wr.rw.src.sge = &wr->remote_sge;
    wr->send_wr.rw.src.num_sge = 1;
    wr->send_wr.rw.dst.sge = &wr->sge;
    wr->send_wr.rw.dst.num_sge = 1;
    status = urma_post_jetty_send_wr(jetty->jetty, &wr->send_wr, &bad_wr);
    if (status != URMA_SUCCESS && bad_wr == &wr->send_wr) {
        dfurma_wr_return(wr);
        return (int)status;
    }
    /* Success, or an ambiguous error without a known rejected WR: retain all
     * references. The caller must quarantine an ambiguous post, not recycle it. */
    dfurma_wr_posted(wr);
    *out = wr;
    return (int)status;
}

static int dfurma_post_send_common(dfurma_jetty_t *jetty,
                                   dfurma_target_t *target,
                                   dfurma_segment_t *segment,
                                   uint64_t offset, uint32_t length,
                                   uint64_t user_ctx, uint64_t imm_data,
                                   uint8_t with_imm, dfurma_wr_t **out)
{
    dfurma_wr_t *wr;
    urma_jfs_wr_t *bad_wr = NULL;
    urma_status_t status;
    int create_status;

    if (jetty == NULL || target == NULL || target->target == NULL ||
        target->jetty != jetty) {
        return -ENOTCONN;
    }
    create_status = dfurma_wr_acquire(jetty, segment, offset, length, &wr);
    if (create_status != 0) {
        return create_status;
    }
    wr->send_wr.opcode = with_imm != 0 ? URMA_OPC_SEND_IMM : URMA_OPC_SEND;
    wr->send_wr.flag.value = 0;
    wr->send_wr.flag.bs.complete_enable = 1;
    wr->target = target;
    wr->send_wr.tjetty = target->target;
    wr->send_wr.user_ctx = user_ctx;
    wr->send_wr.send.src.sge = &wr->sge;
    wr->send_wr.send.src.num_sge = 1;
    wr->send_wr.send.imm_data = imm_data;
    wr->send_wr.next = NULL;
    status = urma_post_jetty_send_wr(jetty->jetty, &wr->send_wr, &bad_wr);
    if (status != URMA_SUCCESS) {
        dfurma_wr_return(wr);
        return (int)status;
    }
    dfurma_wr_posted(wr);
    *out = wr;
    return 0;
}

int dfurma_post_send(dfurma_jetty_t *jetty, dfurma_target_t *target,
                     dfurma_segment_t *segment, uint64_t offset,
                     uint32_t length, uint64_t user_ctx,
                     dfurma_wr_t **out)
{
    return dfurma_post_send_common(jetty, target, segment, offset, length, user_ctx,
                                   0, 0, out);
}

int dfurma_post_send_imm(dfurma_jetty_t *jetty, dfurma_target_t *target,
                         dfurma_segment_t *segment, uint64_t offset,
                         uint32_t length, uint64_t user_ctx,
                         uint64_t imm_data, dfurma_wr_t **out)
{
    return dfurma_post_send_common(jetty, target, segment, offset, length, user_ctx,
                                   imm_data, 1, out);
}

int dfurma_post_recv(dfurma_jetty_t *jetty,
                       dfurma_segment_t *segment, uint64_t offset,
                       uint32_t length, uint64_t user_ctx,
                       dfurma_wr_t **out)
{
    dfurma_wr_t *wr;
    urma_jfr_wr_t *bad_wr = NULL;
    urma_status_t status;
    int create_status = dfurma_wr_acquire(jetty, segment, offset, length, &wr);

    if (create_status != 0) {
        return create_status;
    }
    wr->recv_wr.src.sge = &wr->sge;
    wr->recv_wr.src.num_sge = 1;
    wr->recv_wr.user_ctx = user_ctx;
    wr->recv_wr.next = NULL;
    status = urma_post_jetty_recv_wr(jetty->jetty, &wr->recv_wr, &bad_wr);
    if (status != URMA_SUCCESS) {
        dfurma_wr_return(wr);
        return (int)status;
    }
    dfurma_wr_posted(wr);
    *out = wr;
    return 0;
}

static void dfurma_wr_return_range(dfurma_wr_t **wr_list, uint32_t begin,
                                   uint32_t end)
{
    uint32_t i;

    for (i = begin; i < end; ++i) {
        dfurma_wr_return(wr_list[i]);
    }
}

static int dfurma_post_list_prepare(dfurma_jetty_t *jetty,
                                    dfurma_segment_t *segment,
                                    const dfurma_post_entry_t *entries,
                                    uint32_t count, dfurma_wr_t **wr_list,
                                    dfurma_wr_t **out, uint32_t *posted)
{
    uint32_t i;
    int status;

    if (jetty == NULL || segment == NULL || entries == NULL || out == NULL ||
        posted == NULL || count == 0 || count > DFURMA_MAX_POST_LIST) {
        return -EINVAL;
    }
    *posted = 0;
    for (i = 0; i < count; ++i) {
        out[i] = NULL;
        status = dfurma_wr_acquire(jetty, segment, entries[i].offset,
                                   entries[i].length, &wr_list[i]);
        if (status != 0) {
            dfurma_wr_return_range(wr_list, 0, i);
            return status;
        }
    }
    return 0;
}

static int dfurma_post_send_list_common(dfurma_jetty_t *jetty,
                                        dfurma_target_t *target,
                                        dfurma_segment_t *segment,
                                        const dfurma_post_entry_t *entries,
                                        uint32_t count, uint8_t with_imm,
                                        dfurma_wr_t **out, uint32_t *posted)
{
    dfurma_wr_t *wr_list[DFURMA_MAX_POST_LIST];
    urma_jfs_wr_t *bad_wr = NULL;
    urma_status_t status;
    int result_status;
    uint32_t prefix = 0;
    uint32_t i;
    int prepare_status;

    if (jetty == NULL || target == NULL || target->target == NULL ||
        target->jetty != jetty) {
        return -ENOTCONN;
    }
    prepare_status = dfurma_post_list_prepare(jetty, segment, entries, count,
                                              wr_list, out, posted);
    if (prepare_status != 0) {
        return prepare_status;
    }
    for (i = 0; i < count; ++i) {
        dfurma_wr_t *wr = wr_list[i];
        wr->send_wr.opcode =
            with_imm != 0 ? URMA_OPC_SEND_IMM : URMA_OPC_SEND;
        wr->send_wr.flag.value = 0;
        wr->send_wr.flag.bs.complete_enable = 1;
        wr->target = target;
        wr->send_wr.tjetty = target->target;
        wr->send_wr.user_ctx = entries[i].user_ctx;
        wr->send_wr.send.src.sge = &wr->sge;
        wr->send_wr.send.src.num_sge = 1;
        wr->send_wr.send.imm_data =
            with_imm != 0 ? entries[i].imm_data : 0;
        wr->send_wr.next = i + 1 < count ? &wr_list[i + 1]->send_wr : NULL;
    }

    status = urma_post_jetty_send_wr(jetty->jetty, &wr_list[0]->send_wr,
                                     &bad_wr);
    result_status = (int)status;
    if (status == URMA_SUCCESS) {
        prefix = count;
    } else {
        for (i = 0; i < count; ++i) {
            if (bad_wr == &wr_list[i]->send_wr) {
                prefix = i;
                break;
            }
        }
        if (bad_wr == NULL || i == count) {
            /* Ownership is ambiguous on a broken provider contract. Retain
             * every WR as outstanding so teardown cannot free live metadata. */
            prefix = count;
            result_status = -EPROTO;
        }
    }
    for (i = 0; i < prefix; ++i) {
        dfurma_wr_posted(wr_list[i]);
        out[i] = wr_list[i];
    }
    dfurma_wr_return_range(wr_list, prefix, count);
    *posted = prefix;
    return result_status;
}

int dfurma_post_send_list(dfurma_jetty_t *jetty, dfurma_target_t *target,
                          dfurma_segment_t *segment,
                          const dfurma_post_entry_t *entries, uint32_t count,
                          dfurma_wr_t **out, uint32_t *posted)
{
    return dfurma_post_send_list_common(jetty, target, segment, entries, count, 0,
                                        out, posted);
}

int dfurma_post_send_imm_list(dfurma_jetty_t *jetty, dfurma_target_t *target,
                              dfurma_segment_t *segment,
                              const dfurma_post_entry_t *entries,
                              uint32_t count, dfurma_wr_t **out,
                              uint32_t *posted)
{
    return dfurma_post_send_list_common(jetty, target, segment, entries, count, 1,
                                        out, posted);
}

int dfurma_post_recv_list(dfurma_jetty_t *jetty,
                          dfurma_segment_t *segment,
                          const dfurma_post_entry_t *entries, uint32_t count,
                          dfurma_wr_t **out, uint32_t *posted)
{
    dfurma_wr_t *wr_list[DFURMA_MAX_POST_LIST];
    urma_jfr_wr_t *bad_wr = NULL;
    urma_status_t status;
    int result_status;
    uint32_t prefix = 0;
    uint32_t i;
    int prepare_status = dfurma_post_list_prepare(
        jetty, segment, entries, count, wr_list, out, posted);

    if (prepare_status != 0) {
        return prepare_status;
    }
    for (i = 0; i < count; ++i) {
        dfurma_wr_t *wr = wr_list[i];
        wr->recv_wr.src.sge = &wr->sge;
        wr->recv_wr.src.num_sge = 1;
        wr->recv_wr.user_ctx = entries[i].user_ctx;
        wr->recv_wr.next = i + 1 < count ? &wr_list[i + 1]->recv_wr : NULL;
    }

    status = urma_post_jetty_recv_wr(jetty->jetty, &wr_list[0]->recv_wr,
                                     &bad_wr);
    result_status = (int)status;
    if (status == URMA_SUCCESS) {
        prefix = count;
    } else {
        for (i = 0; i < count; ++i) {
            if (bad_wr == &wr_list[i]->recv_wr) {
                prefix = i;
                break;
            }
        }
        if (bad_wr == NULL || i == count) {
            prefix = count;
            result_status = -EPROTO;
        }
    }
    for (i = 0; i < prefix; ++i) {
        dfurma_wr_posted(wr_list[i]);
        out[i] = wr_list[i];
    }
    dfurma_wr_return_range(wr_list, prefix, count);
    *posted = prefix;
    return result_status;
}

void dfurma_wr_complete(dfurma_wr_t *wr)
{
    if (wr == NULL) {
        return;
    }
    if (wr->runtime->outstanding_wr_count > 0) {
        wr->runtime->outstanding_wr_count--;
    }
    if (wr->segment->outstanding_wr_count > 0) {
        wr->segment->outstanding_wr_count--;
    }
    if (wr->jetty->outstanding_wr_count > 0) {
        wr->jetty->outstanding_wr_count--;
    }
    if (wr->target != NULL && wr->target->outstanding_wr_count > 0) {
        wr->target->outstanding_wr_count--;
    }
    if (wr->read_segment != NULL && wr->read_segment->outstanding_wr_count > 0) {
        wr->read_segment->outstanding_wr_count--;
    }
    dfurma_wr_return(wr);
}

int dfurma_jfc_poll(dfurma_jfc_t *jfc, uint32_t capacity,
                      dfurma_completion_t *out)
{
    urma_cr_t cr[16] = {0};
    uint32_t i;
    int count;

    if (jfc == NULL || jfc->jfc == NULL || out == NULL ||
        capacity == 0 || capacity > 16) {
        return -EINVAL;
    }
    count = urma_poll_jfc(jfc->jfc, (int)capacity, cr);
    if (count <= 0) {
        return count;
    }
    for (i = 0; i < (uint32_t)count; ++i) {
        (void)memset(&out[i], 0, sizeof(out[i]));
        out[i].status = (int32_t)cr[i].status;
        out[i].opcode = (uint32_t)cr[i].opcode;
        out[i].user_ctx = cr[i].user_ctx;
        out[i].imm_data = cr[i].imm_data;
        out[i].completion_len = cr[i].completion_len;
        out[i].local_id = cr[i].local_id;
        memcpy(out[i].remote_eid, cr[i].remote_id.eid.raw,
               DFURMA_EID_SIZE);
        out[i].remote_uasid = cr[i].remote_id.uasid;
        out[i].remote_jetty_id = cr[i].remote_id.id;
        out[i].is_recv = cr[i].flag.bs.s_r;
        out[i].is_jetty = cr[i].flag.bs.jetty;
        out[i].user_ctx_valid =
            (cr[i].status != URMA_CR_WR_SUSPEND_DONE &&
             cr[i].status != URMA_CR_WR_FLUSH_ERR_DONE);
        out[i].imm_data_valid =
            (cr[i].status == URMA_SUCCESS && cr[i].flag.bs.s_r != 0 &&
             cr[i].opcode == URMA_CR_OPC_SEND_WITH_IMM);
        out[i].remote_id_valid =
            (cr[i].status == URMA_SUCCESS && cr[i].flag.bs.s_r != 0);
        if (cr[i].status == URMA_CR_WR_SUSPEND_DONE) {
            out[i].event_kind = DFURMA_COMPLETION_WR_SUSPEND_DONE;
        } else if (cr[i].status == URMA_CR_WR_FLUSH_ERR_DONE) {
            out[i].event_kind = DFURMA_COMPLETION_WR_FLUSH_ERR_DONE;
        } else {
            out[i].event_kind = DFURMA_COMPLETION_WR;
        }
    }
    return count;
}

int dfurma_runtime_close(dfurma_runtime_t *runtime)
{
    urma_status_t status;

    if (runtime == NULL) {
        return -EINVAL;
    }
    if (runtime->jetty_count != 0 || runtime->segment_count != 0 ||
        runtime->outstanding_wr_count != 0 ||
        runtime->jfc_count != 0) {
        return -EBUSY;
    }

    if (runtime->context != NULL) {
        status = urma_delete_context(runtime->context);
        if (status != URMA_SUCCESS) {
            /*
             * Do not unload provider code while a context may still refer to
             * ctx->ops. Keep the wrapper allocated and owned by the caller so
             * close remains retryable instead of creating a dangling handle.
             */
            return (int)status;
        }
        runtime->context = NULL;
    }

    status = urma_uninit();
    if (status != URMA_SUCCESS) {
        /*
         * Closing a shim handle is retryable on every error. In particular,
         * keep the wrapper alive after urma_uninit() fails; the Rust owner
         * retains the pointer and may call close again. Freeing it here would
         * leave Rust holding a dangling pointer and make Drop close it twice.
         */
        return (int)status;
    }

    free(runtime);
    return 0;
}
