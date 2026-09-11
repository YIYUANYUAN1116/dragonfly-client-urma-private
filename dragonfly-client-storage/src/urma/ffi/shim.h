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

#ifndef DFURMA_SHIM_H
#define DFURMA_SHIM_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct dfurma_runtime dfurma_runtime_t;
typedef struct dfurma_jfc dfurma_jfc_t;
typedef struct dfurma_segment dfurma_segment_t;
typedef struct dfurma_jetty dfurma_jetty_t;
typedef struct dfurma_target dfurma_target_t;
typedef struct dfurma_wr dfurma_wr_t;
typedef struct dfurma_read_segment dfurma_read_segment_t;
typedef struct dfurma_read_source dfurma_read_source_t;

/* Rust-owned capability DTO. No pointer in this object belongs to liburma. */
typedef struct dfurma_device_capability {
    int32_t transport_type;
    uint32_t transport_modes;
    uint32_t max_jfc;
    uint32_t max_jfs;
    uint32_t max_jfr;
    uint32_t max_jetty;
    uint32_t max_jfc_depth;
    uint32_t max_jfs_depth;
    uint32_t max_jfr_depth;
    uint32_t max_jfs_sge;
    uint32_t max_jfs_rsge;
    uint32_t max_jfr_sge;
    uint64_t max_msg_size;
    uint32_t max_read_size;
    uint32_t max_write_size;
} dfurma_device_capability_t;

typedef struct dfurma_jetty_config {
    uint32_t send_depth;
    uint32_t recv_depth;
    uint32_t max_send_sge;
    uint32_t max_recv_sge;
    uint32_t token;
    uint32_t tp_type;
} dfurma_jetty_config_t;

typedef struct dfurma_jetty_descriptor_meta {
    uint32_t transport_type;
    uint32_t tp_type;
    uint32_t eid_index;
    uint32_t jetty_id;
    uint32_t opaque_len;
} dfurma_jetty_descriptor_meta_t;

#define DFURMA_TP_RTP 0U
#define DFURMA_TP_CTP 1U

#define DFURMA_EID_SIZE 16U

/* Explicit DTO fields, not a memcpy of a provider ABI structure. Version 1 only
 * represents pinned, non-cacheable READ/plain-token Segments without extensions.
 * Segment/peer generations are checked by the outer transfer registry. */
#define DFURMA_READ_DESCRIPTOR_VERSION 1U
#define DFURMA_READ_ACCESS 2U
#define DFURMA_READ_TOKEN_PLAIN 1U
typedef struct dfurma_read_descriptor {
    uint32_t version;
    uint8_t eid[DFURMA_EID_SIZE];
    uint32_t uasid;
    uint64_t va;
    uint64_t length;
    uint32_t token_id;
    uint32_t access;
    uint32_t token_policy;
} dfurma_read_descriptor_t;

/* External immutable backing is caller-owned throughout registration, retirement
 * and revocation confirmation. No function below frees the backing allocation.
 * On a registration error with non-NULL *out, native grant cleanup is uncertain:
 * retain the wrapper AND backing. NULL *out means registration was never called. */
int dfurma_read_source_register(dfurma_runtime_t *runtime, const uint8_t *data,
                                uint64_t length, uint32_t token,
                                dfurma_read_source_t **out);
int dfurma_read_source_descriptor(dfurma_read_source_t *source,
                                  dfurma_read_descriptor_t *out);
/* Stops descriptor export; success means native unregister only, not revocation.
 * Wrapper, explicitly owned token ID, backing and runtime count remain retained.
 * Registration-uncertain sources cannot be unregistered using a missing handle. */
int dfurma_read_source_unregister(dfurma_read_source_t *source);
/* CALLER MUST independently prove remote access has ceased and cannot resume.
 * Only accepts sources without a live native registration; releases token ID and
 * wrapper on success. Caller may release backing only after this also succeeds. */
int dfurma_read_source_release_after_revoke(dfurma_read_source_t *source);

/* Validates the supported descriptor subset and peer identity before import.
 * max_read_size is the negotiated limit; zero never means unlimited. */
int dfurma_read_segment_import(dfurma_target_t *target,
                               const dfurma_read_descriptor_t *descriptor,
                               uint32_t token, uint32_t max_read_size,
                               dfurma_read_segment_t **out);
/* Refuses unimport while any READ owner is outstanding. Success only closes the
 * local import; it is not evidence of remote revocation. */
int dfurma_read_segment_unimport(dfurma_read_segment_t *segment);
/* On an indeterminate provider post error, returns an error AND a non-NULL WR.
 * That WR holds all dependencies until CQE/verified retirement; never discard it
 * as an unposted request. A known unaccepted WR returns an error and NULL. */
int dfurma_post_read(dfurma_jetty_t *jetty, dfurma_target_t *target,
                     dfurma_segment_t *local, dfurma_read_segment_t *remote,
                     uint64_t local_offset, uint64_t remote_offset,
                     uint32_t length, uint64_t user_ctx, dfurma_wr_t **out);

/* Pointer-free completion DTO copied from urma_cr_t by the C shim. */
typedef struct dfurma_completion {
    int32_t status;
    uint32_t opcode;
    uint64_t user_ctx;
    uint64_t imm_data;
    uint32_t completion_len;
    uint32_t local_id;
    uint8_t remote_eid[DFURMA_EID_SIZE];
    uint32_t remote_uasid;
    uint32_t remote_jetty_id;
    uint8_t is_recv;
    uint8_t is_jetty;
    uint8_t user_ctx_valid;
    uint8_t imm_data_valid;
    uint8_t remote_id_valid;
    uint8_t event_kind;
    uint8_t reserved[2];
} dfurma_completion_t;

/* Stable receive CQE opcode values, checked against UMDK by shim.c. */
#define DFURMA_CR_OPC_SEND_WITH_IMM 1U

enum dfurma_completion_event_kind {
    DFURMA_COMPLETION_WR = 0,
    DFURMA_COMPLETION_WR_SUSPEND_DONE = 1,
    DFURMA_COMPLETION_WR_FLUSH_ERR_DONE = 2,
};

/* One pointer-free element in a linked WR post list. */
typedef struct dfurma_post_entry {
    uint64_t offset;
    uint32_t length;
    uint64_t user_ctx;
    uint64_t imm_data;
} dfurma_post_entry_t;

/* Bounds shim stack storage and the maximum native doorbell batch. */
#define DFURMA_MAX_POST_LIST 64

/*
 * Opens the smallest process-global chain: urma_init -> device -> context.
 * `device_name` must be NUL terminated and `out` must be a valid writable pointer.
 * On success, ownership of *out is transferred to the caller.
 */
int dfurma_runtime_open(const char *device_name, uint32_t eid_index,
                        dfurma_runtime_t **out);

/* Queries public device fields and copies them into a pointer-free DTO. */
int dfurma_runtime_query_device(dfurma_runtime_t *runtime,
                                dfurma_device_capability_t *out);

/* Creates a polling JFC. No JFCE is allocated for the Phase A data path. */
int dfurma_jfc_create(dfurma_runtime_t *runtime, uint32_t depth,
                      dfurma_jfc_t **out);

int dfurma_jfc_delete(dfurma_jfc_t *jfc);

/* Allocates aligned zeroed memory, then registers it as local-only memory. */
int dfurma_segment_create(dfurma_runtime_t *runtime, uint64_t length,
                          uint64_t alignment, dfurma_segment_t **out);

/* Unregisters the Segment before releasing its backing allocation. */
int dfurma_segment_delete(dfurma_segment_t *segment);
/* Returns the CPU-visible backing range owned by the live Segment wrapper. */
int dfurma_segment_data(dfurma_segment_t *segment, uint8_t **data,
                        uint64_t *length);

/* Creates one RM duplex Jetty backed by an owned shared JFR. */
int dfurma_jetty_create(dfurma_runtime_t *runtime,
                        dfurma_jfc_t *send_jfc,
                        dfurma_jfc_t *recv_jfc,
                        const dfurma_jetty_config_t *config,
                        dfurma_jetty_t **out);

/* Moves both the Jetty and its owned shared JFR to ERROR. */
int dfurma_jetty_mark_error(dfurma_jetty_t *jetty);
/* Returns the provider IDs used to route shared-JFC lifecycle completions. */
int dfurma_jetty_local_ids(dfurma_jetty_t *jetty,
                           uint32_t *jetty_id, uint32_t *jfr_id);

int dfurma_jetty_export_descriptor(dfurma_jetty_t *jetty,
                                   dfurma_jetty_descriptor_meta_t *meta,
                                   uint8_t **opaque_data);
void dfurma_descriptor_free(uint8_t *opaque_data);

int dfurma_jetty_import(dfurma_jetty_t *jetty,
                        const dfurma_jetty_descriptor_meta_t *meta,
                        const uint8_t *opaque_data, uint32_t opaque_len,
                        uint32_t token, dfurma_target_t **out);
int dfurma_target_remote_id(dfurma_target_t *target,
                            uint8_t eid[DFURMA_EID_SIZE], uint32_t *uasid,
                            uint32_t *jetty_id);
int dfurma_target_unimport(dfurma_target_t *target);
int dfurma_jetty_delete(dfurma_jetty_t *jetty);

/*
 * These functions build bitfield/union-bearing UMDK WR/SGE objects in C.
 * The returned owner must remain alive until its CQE is consumed.
 */
int dfurma_post_send(dfurma_jetty_t *jetty, dfurma_target_t *target,
                     dfurma_segment_t *segment, uint64_t offset,
                     uint32_t length, uint64_t user_ctx,
                     dfurma_wr_t **out);
int dfurma_post_send_imm(dfurma_jetty_t *jetty, dfurma_target_t *target,
                         dfurma_segment_t *segment, uint64_t offset,
                         uint32_t length, uint64_t user_ctx,
                         uint64_t imm_data, dfurma_wr_t **out);
int dfurma_post_recv(dfurma_jetty_t *jetty,
                     dfurma_segment_t *segment, uint64_t offset,
                     uint32_t length, uint64_t user_ctx,
                     dfurma_wr_t **out);
/*
 * Posts an ordered linked list. `posted` is always the successfully submitted
 * prefix, including when the provider returns an error and `bad_wr` identifies
 * the first unsubmitted entry. Only out[0..*posted] contain owned WR handles.
 */
int dfurma_post_send_list(dfurma_jetty_t *jetty, dfurma_target_t *target,
                          dfurma_segment_t *segment,
                          const dfurma_post_entry_t *entries, uint32_t count,
                          dfurma_wr_t **out, uint32_t *posted);
int dfurma_post_send_imm_list(dfurma_jetty_t *jetty, dfurma_target_t *target,
                              dfurma_segment_t *segment,
                              const dfurma_post_entry_t *entries,
                              uint32_t count, dfurma_wr_t **out,
                              uint32_t *posted);
int dfurma_post_recv_list(dfurma_jetty_t *jetty,
                          dfurma_segment_t *segment,
                          const dfurma_post_entry_t *entries, uint32_t count,
                          dfurma_wr_t **out, uint32_t *posted);
void dfurma_wr_complete(dfurma_wr_t *wr);

/* Non-blocking poll. Returns a count in [0, capacity], or a negative error. */
int dfurma_jfc_poll(dfurma_jfc_t *jfc, uint32_t capacity,
                    dfurma_completion_t *out);

/*
 * Destroys context before urma_uninit and frees the wrapper. The pointer must be
 * a unique live value returned by dfurma_runtime_open.
 */
int dfurma_runtime_close(dfurma_runtime_t *runtime);

#ifdef __cplusplus
}
#endif

#endif /* DFURMA_SHIM_H */
