/* Offline tests of the real shim against deterministic provider-call doubles.
 * No device/context is opened. This is not evidence of hardware READ semantics. */
#define urma_delete_context test_delete_context
#define urma_uninit test_uninit
#define urma_query_device test_query_device
#define urma_import_seg test_import_seg
#define urma_unimport_seg test_unimport_seg
#define urma_post_jetty_send_wr test_post_read
#define urma_post_jetty_recv_wr test_post_recv
#define urma_alloc_token_id test_alloc_token
#define urma_free_token_id test_free_token
#define urma_register_seg test_register_source
#define urma_unregister_seg test_unregister_source
#define urma_get_seg_ctx test_get_seg_ctx
#define urma_put_seg_ctx test_put_seg_ctx
#define urma_delete_jetty test_delete_jetty
#define urma_delete_jfr test_delete_jfr
#include "../src/urma/ffi/shim.c"

#include <assert.h>
#include <stdio.h>

static unsigned int imports;
static unsigned int unimports;
static unsigned int posts;
static int post_mode; /* 0 accepted; 1 known rejected; 2 indeterminate */
static int fail_unimport;
static int fail_import;
static uint32_t device_read_limit;
static unsigned char source[32];
static int fail_register;
static int fail_unregister;
static int fail_token_alloc;
static int fail_token_free;
static unsigned int token_allocations;
static unsigned int token_frees;
static unsigned int unregister_calls;
static unsigned int context_frees;
static int context_mode;
static int destroy_failure;
static unsigned int destroyed_jetty, destroyed_jfr;

urma_status_t test_delete_jetty(urma_jetty_t *jetty)
{
    assert(jetty != NULL);
    if (destroy_failure == 1) return URMA_FAIL;
    destroyed_jetty++;
    return URMA_SUCCESS;
}

urma_status_t test_delete_jfr(urma_jfr_t *jfr)
{
    assert(jfr != NULL);
    if (destroy_failure == 2) return URMA_FAIL;
    destroyed_jfr++;
    return URMA_SUCCESS;
}

urma_status_t test_delete_context(urma_context_t *ctx)
{
    assert(ctx != NULL);
    return URMA_SUCCESS;
}

urma_status_t test_uninit(void)
{
    return URMA_SUCCESS;
}

urma_token_id_t *test_alloc_token(urma_context_t *ctx)
{
    urma_token_id_t *id;
    if (fail_token_alloc) {
        errno = ENOMEM;
        return NULL;
    }
    id = calloc(1, sizeof(*id));
    assert(id != NULL);
    id->urma_ctx = ctx;
    id->token_id = 123;
    token_allocations++;
    return id;
}

urma_status_t test_free_token(urma_token_id_t *token)
{
    if (fail_token_free) {
        return URMA_FAIL;
    }
    free(token);
    token_frees++;
    return URMA_SUCCESS;
}

urma_target_seg_t *test_register_source(urma_context_t *ctx, urma_seg_cfg_t *cfg)
{
    urma_target_seg_t *seg;
    if (cfg->flag.bs.access == URMA_ACCESS_LOCAL_ONLY) {
        assert(cfg->flag.bs.token_policy == URMA_TOKEN_NONE);
        if (fail_register) { errno = EIO; return NULL; }
        seg = calloc(1, sizeof(*seg));
        assert(seg != NULL);
        seg->urma_ctx = ctx;
        return seg;
    }
    assert(cfg->flag.bs.access == URMA_ACCESS_READ);
    assert(cfg->flag.bs.token_policy == URMA_TOKEN_PLAIN_TEXT);
    assert(cfg->flag.bs.token_id_valid == URMA_TOKEN_ID_VALID && cfg->token_id != NULL);
    assert(!cfg->flag.bs.non_pin && !cfg->flag.bs.cacheable);
    assert(cfg->token_value.token == 0x12345678);
    if (fail_register) {
        errno = EIO;
        return NULL;
    }
    seg = calloc(1, sizeof(*seg));
    assert(seg != NULL);
    seg->urma_ctx = ctx;
    seg->token_id = cfg->token_id;
    seg->seg.ubva.eid.raw[0] = 42;
    seg->seg.ubva.uasid = 3;
    seg->seg.ubva.va = cfg->va;
    seg->seg.len = cfg->len;
    seg->seg.attr.bs.access = URMA_ACCESS_READ;
    seg->seg.attr.bs.token_policy = URMA_TOKEN_PLAIN_TEXT;
    seg->seg.attr.bs.user_token_id = URMA_TOKEN_ID_VALID;
    seg->seg.token_id = cfg->token_id->token_id;
    return seg;
}

urma_status_t test_unregister_source(urma_target_seg_t *seg)
{
    unregister_calls++;
    if (fail_unregister) {
        return URMA_FAIL;
    }
    free(seg);
    return URMA_SUCCESS;
}

urma_status_t test_get_seg_ctx(urma_target_seg_t *source_seg, urma_seg_t **out, uint32_t *size)
{
    urma_seg_t *seg = malloc(sizeof(*seg));
    assert(seg != NULL);
    *seg = source_seg->seg;
    *size = sizeof(*seg);
    switch (context_mode) {
    case 1: seg->attr.bs.has_user_info = 1; break;
    case 2: seg->attr.bs.non_pin = 1; break;
    case 3: seg->attr.bs.cacheable = 1; break;
    case 4: seg->attr.bs.access |= URMA_ACCESS_WRITE; break;
    case 5: seg->ubva.va--; break;
    case 6: seg->len++; break;
    case 7: *size += 8; break;
    default: break;
    }
    *out = seg;
    return URMA_SUCCESS;
}

void test_put_seg_ctx(urma_seg_t *seg)
{
    free(seg);
    context_frees++;
}

urma_status_t test_query_device(urma_device_t *device, urma_device_attr_t *attr)
{
    (void)device;
    memset(attr, 0, sizeof(*attr));
    attr->dev_cap.trans_mode = URMA_TM_RM;
    attr->dev_cap.max_read_size = device_read_limit;
    attr->dev_cap.max_jfs_sge = 1;
    attr->dev_cap.max_jfs_rsge = 1;
    return URMA_SUCCESS;
}

urma_target_seg_t *test_import_seg(urma_context_t *ctx, urma_seg_t *seg,
                                  urma_token_t *token, uint64_t addr,
                                  urma_import_seg_flag_t flag)
{
    urma_target_seg_t *result;
    imports++;
    assert(token->token == 0x12345678);
    assert(addr == 0 && flag.bs.mapping == URMA_SEG_NOMAP);
    assert(flag.bs.access == URMA_ACCESS_READ);
    assert(seg->attr.bs.access == URMA_ACCESS_READ);
    assert(seg->attr.bs.token_policy == URMA_TOKEN_PLAIN_TEXT);
    assert(!seg->attr.bs.non_pin && !seg->attr.bs.has_user_info);
    if (fail_import) {
        errno = ENOMEM;
        return NULL;
    }
    result = calloc(1, sizeof(*result));
    assert(result != NULL);
    result->seg = *seg;
    result->urma_ctx = ctx;
    return result;
}

urma_status_t test_unimport_seg(urma_target_seg_t *segment)
{
    unimports++;
    if (fail_unimport) {
        return URMA_FAIL;
    }
    free(segment);
    return URMA_SUCCESS;
}

urma_status_t test_post_read(urma_jetty_t *jetty, urma_jfs_wr_t *wr,
                             urma_jfs_wr_t **bad_wr)
{
    (void)jetty;
    posts++;
    if (wr->opcode == URMA_OPC_SEND) {
        assert(wr->flag.bs.complete_enable == 1 && wr->tjetty != NULL);
        assert(wr->user_ctx == 0xabcdef && wr->next == NULL);
        assert(wr->send.src.num_sge == 1 && wr->send.src.sge->len == 8);
        assert(wr->send.src.sge->tseg != NULL);
        *bad_wr = post_mode == 1 ? wr : NULL;
        return post_mode ? URMA_FAIL : URMA_SUCCESS;
    }
    assert(wr->opcode == URMA_OPC_READ && wr->flag.bs.complete_enable == 1);
    assert(wr->next == NULL && wr->tjetty != NULL);
    assert(wr->user_ctx == 0xabcdef);
    assert(wr->rw.src.num_sge == 1 && wr->rw.dst.num_sge == 1);
    assert(wr->rw.src.sge->tseg != NULL && wr->rw.dst.sge->tseg != NULL);
    assert(wr->rw.src.sge->len == wr->rw.dst.sge->len);
    if (post_mode == 1) {
        *bad_wr = wr;
        return URMA_FAIL;
    }
    /* Simulated payload copy checks READ source/destination orientation only. */
    memcpy((void *)(uintptr_t)wr->rw.dst.sge->addr,
           (void *)(uintptr_t)wr->rw.src.sge->addr, wr->rw.src.sge->len);
    *bad_wr = NULL;
    return post_mode == 2 ? URMA_FAIL : URMA_SUCCESS;
}

urma_status_t test_post_recv(urma_jetty_t *jetty, urma_jfr_wr_t *wr,
                            urma_jfr_wr_t **bad_wr)
{
    (void)jetty;
    assert(wr->next == NULL && wr->user_ctx == 0xabcdef);
    assert(wr->src.num_sge == 1 && wr->src.sge->len == 8 && wr->src.sge->tseg != NULL);
    *bad_wr = post_mode == 1 ? wr : NULL;
    return post_mode ? URMA_FAIL : URMA_SUCCESS;
}

struct fixture {
    urma_device_t device;
    urma_context_t context;
    urma_jetty_t native_jetty;
    urma_target_jetty_t native_target;
    urma_target_seg_t native_local;
    dfurma_runtime_t runtime;
    dfurma_jetty_t jetty;
    dfurma_target_t target;
    dfurma_segment_t local;
    dfurma_wr_t arena[2];
    dfurma_read_descriptor_t descriptor;
    unsigned char destination[32];
};

static void setup(struct fixture *f)
{
    memset(f, 0, sizeof(*f));
    imports = unimports = posts = 0;
    post_mode = fail_unimport = fail_import = 0;
    fail_register = fail_unregister = fail_token_alloc = fail_token_free = context_mode = 0;
    token_allocations = token_frees = unregister_calls = context_frees = 0;
    device_read_limit = 16;
    memset(source, 0x5a, sizeof(source));
    f->runtime.device = &f->device;
    f->runtime.context = &f->context;
    f->runtime.segment_count = 1; /* local Segment */
    f->runtime.jetty_count = 1;
    f->jetty.runtime = &f->runtime;
    f->jetty.jetty = &f->native_jetty;
    f->jetty.target_count = 1;
    f->jetty.free_wr = &f->arena[0];
    f->arena[0].next_free = &f->arena[1];
    f->target.jetty = &f->jetty;
    f->target.target = &f->native_target;
    f->native_target.id.eid.raw[0] = 42;
    f->native_target.id.uasid = 3;
    f->local.runtime = &f->runtime;
    f->local.segment = &f->native_local;
    f->local.memory = f->destination;
    f->local.length = sizeof(f->destination);
    f->descriptor.version = DFURMA_READ_DESCRIPTOR_VERSION;
    f->descriptor.eid[0] = 42;
    f->descriptor.uasid = 3;
    f->descriptor.va = (uint64_t)(uintptr_t)source;
    f->descriptor.length = sizeof(source);
    f->descriptor.token_id = 12;
    f->descriptor.access = DFURMA_READ_ACCESS;
    f->descriptor.token_policy = DFURMA_READ_TOKEN_PLAIN;
}

static dfurma_read_segment_t *import_remote(struct fixture *f)
{
    dfurma_read_segment_t *remote = NULL;
    assert(dfurma_read_segment_import(&f->target, &f->descriptor,
                                      0x12345678, 32, &remote) == 0);
    assert(remote != NULL && remote->max_read_size == 16);
    assert(f->runtime.segment_count == 2 && f->target.read_segment_count == 1);
    return remote;
}

static void assert_outstanding(struct fixture *f, dfurma_read_segment_t *remote,
                                unsigned int expected)
{
    assert(f->runtime.outstanding_wr_count == expected);
    assert(f->jetty.outstanding_wr_count == expected);
    assert(f->target.outstanding_wr_count == expected);
    assert(f->local.outstanding_wr_count == expected);
    assert(remote->outstanding_wr_count == expected);
}

static void test_descriptor_validation(void)
{
    struct fixture f;
    dfurma_read_descriptor_t good;
    dfurma_read_segment_t *remote = NULL;
    unsigned int i;
    setup(&f);
    good = f.descriptor;
    for (i = 0; i < 9; i++) {
        f.descriptor = good;
        switch (i) {
        case 0: f.descriptor.version++; break;
        case 1: f.descriptor.access |= URMA_ACCESS_WRITE; break;
        case 2: f.descriptor.token_policy = URMA_TOKEN_NONE; break;
        case 3: f.descriptor.length = 0; break;
        case 4: f.descriptor.va = UINT64_MAX - 1; break;
        case 5: f.descriptor.eid[0]++; break;
        case 6: f.descriptor.uasid++; break;
        case 7: f.descriptor.uasid = 0x1000000; break;
        default: f.descriptor.va = 0; break;
        }
        assert(dfurma_read_segment_import(&f.target, &f.descriptor,
                                          0x12345678, 16, &remote) != 0);
        assert(remote == NULL && imports == 0);
    }
    f.descriptor = good;
    assert(dfurma_read_segment_import(&f.target, &f.descriptor,
                                      0x12345678, 0, &remote) != 0);
    device_read_limit = 0;
    assert(dfurma_read_segment_import(&f.target, &f.descriptor,
                                      0x12345678, 16, &remote) == -EOPNOTSUPP);
    assert(imports == 0);
    device_read_limit = 16;
    fail_import = 1;
    assert(dfurma_read_segment_import(&f.target, &f.descriptor,
                                      0x12345678, 16, &remote) == -ENOMEM);
    assert(remote == NULL && f.runtime.segment_count == 1 && f.target.read_segment_count == 0);
}

static void test_read_ownership_and_retryable_unimport(void)
{
    struct fixture f;
    dfurma_wr_t *wr = NULL;
    dfurma_read_segment_t *remote;
    setup(&f);
    remote = import_remote(&f);
    assert(dfurma_target_unimport(&f.target) == -EBUSY);
    assert(dfurma_post_read(&f.jetty, &f.target, &f.local, remote,
                            3, 5, 8, 0xabcdef, &wr) == 0);
    assert(wr != NULL && posts == 1);
    assert_outstanding(&f, remote, 1);
    assert(memcmp(f.destination + 3, source + 5, 8) == 0);
    assert(f.destination[2] == 0 && f.destination[11] == 0);
    assert(dfurma_read_segment_unimport(remote) == -EBUSY && unimports == 0);
    assert(dfurma_segment_delete(&f.local) == -EBUSY);
    assert(dfurma_target_unimport(&f.target) == -EBUSY);
    dfurma_wr_complete(wr); /* Simulated CQE: no claim about actual hardware. */
    assert_outstanding(&f, remote, 0);
    fail_unimport = 1;
    assert(dfurma_read_segment_unimport(remote) == URMA_FAIL);
    assert(f.target.read_segment_count == 1 && f.runtime.segment_count == 2);
    fail_unimport = 0;
    assert(dfurma_read_segment_unimport(remote) == 0);
    assert(f.target.read_segment_count == 0 && f.runtime.segment_count == 1);
}

static void test_read_preflight(void)
{
    struct fixture f;
    dfurma_wr_t *wr = NULL;
    dfurma_read_segment_t *remote;
    dfurma_target_t other;
    setup(&f);
    remote = import_remote(&f);
    assert(dfurma_post_read(&f.jetty, &f.target, &f.local, remote, 0, 0, 17, 0, &wr) != 0);
    assert(dfurma_post_read(&f.jetty, &f.target, &f.local, remote, 25, 0, 8, 0, &wr) != 0);
    assert(dfurma_post_read(&f.jetty, &f.target, &f.local, remote, 0, 25, 8, 0, &wr) != 0);
    assert(dfurma_post_read(&f.jetty, &f.target, &f.local, remote, 0, UINT64_MAX, 8, 0, &wr) != 0);
    other = f.target;
    assert(dfurma_post_read(&f.jetty, &other, &f.local, remote, 0, 0, 8, 0, &wr) != 0);
    f.jetty.jetty_error = 1;
    assert(dfurma_post_read(&f.jetty, &f.target, &f.local, remote, 0, 0, 8, 0, &wr) == -ESHUTDOWN);
    assert(wr == NULL && posts == 0);
    assert_outstanding(&f, remote, 0);
    assert(dfurma_read_segment_unimport(remote) == 0);
}

static void test_failed_and_ambiguous_post(void)
{
    struct fixture f;
    dfurma_wr_t *wr = NULL;
    dfurma_read_segment_t *remote;
    setup(&f);
    remote = import_remote(&f);
    post_mode = 1;
    assert(dfurma_post_read(&f.jetty, &f.target, &f.local, remote,
                            0, 0, 8, 0xabcdef, &wr) == URMA_FAIL);
    assert(wr == NULL);
    assert_outstanding(&f, remote, 0);
    post_mode = 2;
    assert(dfurma_post_read(&f.jetty, &f.target, &f.local, remote,
                            0, 0, 8, 0xabcdef, &wr) == URMA_FAIL);
    assert(wr != NULL);
    assert_outstanding(&f, remote, 1);
    assert(dfurma_read_segment_unimport(remote) == -EBUSY);
    dfurma_wr_complete(wr); /* Here the double supplies simulated retirement. */
    assert_outstanding(&f, remote, 0);
    assert(dfurma_read_segment_unimport(remote) == 0);
}

static void test_source_to_read_roundtrip_and_separate_release(void)
{
    struct fixture f;
    dfurma_read_source_t *exported = NULL;
    dfurma_read_segment_t *remote = NULL;
    dfurma_wr_t *wr = NULL;
    setup(&f);
    assert(dfurma_read_source_register(&f.runtime, source, sizeof(source),
                                       0x12345678, &exported) == 0);
    assert(token_allocations == 1 && f.runtime.segment_count == 2);
    assert(dfurma_read_source_release_after_revoke(exported) == -EBUSY);
    assert(dfurma_read_source_descriptor(exported, &f.descriptor) == 0);
    assert(context_frees == 1 && f.descriptor.token_id == 123);
    assert(dfurma_read_segment_import(&f.target, &f.descriptor, 0x12345678, 16, &remote) == 0);
    assert(dfurma_post_read(&f.jetty, &f.target, &f.local, remote, 0, 0, 8, 0xabcdef, &wr) == 0);
    assert(memcmp(source, f.destination, 8) == 0);
    dfurma_wr_complete(wr);
    assert(dfurma_read_segment_unimport(remote) == 0);
    assert(dfurma_read_source_unregister(exported) == 0);
    assert(dfurma_read_source_unregister(exported) == 0 && unregister_calls == 1);
    /* Unregister did NOT release token, runtime dependency, or caller backing. */
    assert(token_frees == 0 && f.runtime.segment_count == 2 && source[0] == 0x5a);
    assert(dfurma_read_source_descriptor(exported, &f.descriptor) == -ESHUTDOWN);
    /* Source release drops its shared-token reference; Runtime retains the id. */
    assert(dfurma_read_source_release_after_revoke(exported) == 0);
    assert(f.runtime.segment_count == 1 && token_frees == 0 && source[0] == 0x5a);
    assert(f.runtime.read_token_id_refs == 0 && f.runtime.read_token_id != NULL);
    assert(test_free_token(f.runtime.read_token_id) == URMA_SUCCESS);

}

static void test_source_export_rejects_unrepresented_context(void)
{
    struct fixture f;
    dfurma_read_source_t *exported = NULL;
    setup(&f);
    assert(dfurma_read_source_register(&f.runtime, source, sizeof(source),
                                       0x12345678, &exported) == 0);
    for (context_mode = 1; context_mode <= 7; context_mode++) {
        assert(dfurma_read_source_descriptor(exported, &f.descriptor) != 0);
        assert(f.descriptor.version == 0 && f.descriptor.token_id == 0);
    }
    assert(context_frees == 7);
    assert(dfurma_read_source_unregister(exported) == 0);
    assert(dfurma_read_source_release_after_revoke(exported) == 0);
    assert(f.runtime.read_token_id_refs == 0);
    assert(test_free_token(f.runtime.read_token_id) == URMA_SUCCESS);
}

static void test_source_unregister_failure_keeps_token_and_blocks_export(void)
{
    struct fixture f;
    dfurma_read_source_t *exported = NULL;
    setup(&f);
    assert(dfurma_read_source_register(&f.runtime, source, sizeof(source),
                                       0x12345678, &exported) == 0);
    fail_unregister = 1;
    assert(dfurma_read_source_unregister(exported) == URMA_FAIL);
    assert(dfurma_read_source_descriptor(exported, &f.descriptor) == -ESHUTDOWN);
    assert(dfurma_read_source_release_after_revoke(exported) == -EBUSY);
    assert(token_frees == 0 && f.runtime.segment_count == 2);
    fail_unregister = 0;
    assert(dfurma_read_source_unregister(exported) == 0);
    assert(dfurma_read_source_release_after_revoke(exported) == 0);
    assert(unregister_calls == 2 && token_frees == 0 && f.runtime.read_token_id_refs == 0);
    assert(test_free_token(f.runtime.read_token_id) == URMA_SUCCESS);
}

static void test_registration_failure_retains_uncertain_grants(void)
{
    struct fixture f;
    dfurma_read_source_t *exported = NULL;
    setup(&f);
    assert(dfurma_read_source_register(&f.runtime, source, 0, 0, &exported) == -EINVAL);
    assert(exported == NULL && token_allocations == 0);
    fail_token_alloc = 1;
    assert(dfurma_read_source_register(&f.runtime, source, sizeof(source),
                                       0x12345678, &exported) == -ENOMEM);
    assert(exported == NULL && f.runtime.segment_count == 1);
    fail_token_alloc = 0;
    fail_register = 1;
    assert(dfurma_read_source_register(&f.runtime, source, sizeof(source),
                                       0x12345678, &exported) == -EIO);
    assert(exported != NULL && f.runtime.segment_count == 2);
    assert(token_allocations == 1 && token_frees == 0);
    assert(dfurma_read_source_unregister(exported) == -EUCLEAN && unregister_calls == 0);
    assert(dfurma_read_source_descriptor(exported, &f.descriptor) == -ESHUTDOWN);
    /* An actual provider would require independent rollback/revocation evidence. */
    assert(dfurma_read_source_release_after_revoke(exported) == 0);
    assert(token_frees == 0 && f.runtime.segment_count == 1 && f.runtime.read_token_id_refs == 0);
    assert(test_free_token(f.runtime.read_token_id) == URMA_SUCCESS);
}

static void test_read_buffer_failure_retains_memory_and_runtime(void)
{
    struct fixture f;
    dfurma_segment_t *buffer = NULL;
    setup(&f);
    assert(dfurma_read_buffer_create(&f.runtime, 32, 3, &buffer) == -EINVAL);
    assert(buffer == NULL && f.runtime.segment_count == 1);
    assert(dfurma_read_buffer_create(&f.runtime, 32, 64, &buffer) == 0);
    assert(buffer != NULL && f.runtime.segment_count == 2);
    fail_unregister = 1;
    assert(dfurma_segment_delete(buffer) != 0);
    assert(buffer->memory != NULL && f.runtime.segment_count == 2);
    fail_unregister = 0;
    assert(dfurma_segment_delete(buffer) == 0 && f.runtime.segment_count == 1);
    buffer = NULL;
    fail_register = 1;
    assert(dfurma_read_buffer_create(&f.runtime, 32, 64, &buffer) == -EIO);
    assert(buffer != NULL && buffer->memory != NULL && buffer->segment == NULL);
    assert(f.runtime.segment_count == 2);
    assert(dfurma_segment_delete(buffer) != 0 && f.runtime.segment_count == 2);
    /* Only the test knows no provider resource was created. Production has no
     * unchecked recovery API for this uncertain allocation. */
    free(buffer->memory);
    free(buffer);
    f.runtime.segment_count--;
}

static void test_allocated_read_buffer_full_lifecycle(void)
{
    struct fixture f;
    dfurma_segment_t *buffer = NULL;
    dfurma_read_segment_t *remote = NULL;
    dfurma_wr_t *wr = NULL;
    setup(&f);
    assert(dfurma_read_buffer_create(&f.runtime, 32, 64, &buffer) == 0);
    assert(dfurma_read_segment_import(&f.target, &f.descriptor, 0x12345678, 16, &remote) == 0);
    assert(f.runtime.segment_count == 3);
    assert(dfurma_post_read(&f.jetty, &f.target, buffer, remote, 0, 0, 16, 0xabcdef, &wr) == 0);
    assert(buffer->outstanding_wr_count == 1);
    assert(dfurma_segment_delete(buffer) == -EBUSY);
    assert(dfurma_read_segment_unimport(remote) == -EBUSY);
    assert(memcmp(source, buffer->memory, 16) == 0);
    dfurma_wr_complete(wr);
    assert(buffer->outstanding_wr_count == 0);
    assert(dfurma_read_segment_unimport(remote) == 0);
    assert(dfurma_segment_delete(buffer) == 0);
    assert(f.runtime.segment_count == 1 && f.target.read_segment_count == 0);
}

static void test_source_register_stage_timings(void)
{
    struct fixture f;
    dfurma_read_source_t *exported = NULL;
    dfurma_read_source_stages_t stages;
    uint64_t before, after, total;
    setup(&f);
    assert(dfurma_read_source_register_stages(NULL, &stages) == -EINVAL);
    before = dfurma_monotonic_ns();
    assert(dfurma_read_source_register(&f.runtime, source, sizeof(source),
                                       0x12345678, &exported) == 0);
    after = dfurma_monotonic_ns();
    assert(dfurma_read_source_register_stages(exported, NULL) == -EINVAL);
    assert(dfurma_read_source_register_stages(exported, &stages) == 0);
    /* Same monotonic clock as the shim: sub-phases cannot exceed their window. */
    total = stages.alloc_ns + stages.copy_ns + stages.token_ns + stages.seg_ns;
    assert(after >= before && total <= after - before);
    assert(stages.alloc_ns > 0 || stages.copy_ns > 0);
    /* Diagnostics never disturb the lifecycle staged below. */
    assert(dfurma_read_source_unregister(exported) == 0);
    assert(dfurma_read_source_release_after_revoke(exported) == 0);
    assert(f.runtime.segment_count == 1 && token_frees == 0 && f.runtime.read_token_id_refs == 0);
    assert(test_free_token(f.runtime.read_token_id) == URMA_SUCCESS);
}

static void test_shared_token_lives_until_retryable_runtime_close(void)
{
    struct fixture f;
    dfurma_read_source_t *first = NULL, *second = NULL;
    dfurma_runtime_t *runtime = calloc(1, sizeof(*runtime));
    setup(&f);
    assert(runtime != NULL);
    runtime->device = &f.device;
    runtime->context = &f.context;
    assert(dfurma_read_source_register(runtime, source, sizeof(source), 0x12345678, &first) == 0);
    assert(dfurma_read_source_register(runtime, source, sizeof(source), 0x12345678, &second) == 0);
    assert(token_allocations == 1 && runtime->read_token_id_refs == 2);
    assert(first->token_id == second->token_id);
    assert(dfurma_runtime_close(runtime) == -EBUSY);
    assert(dfurma_read_source_unregister(first) == 0);
    assert(dfurma_read_source_release_after_revoke(first) == 0);
    assert(runtime->read_token_id_refs == 1 && token_frees == 0);
    assert(dfurma_runtime_close(runtime) == -EBUSY);
    assert(dfurma_read_source_unregister(second) == 0);
    assert(dfurma_read_source_release_after_revoke(second) == 0);
    assert(runtime->read_token_id_refs == 0 && token_frees == 0);
    fail_token_free = 1;
    assert(dfurma_runtime_close(runtime) == URMA_FAIL);
    assert(runtime->read_token_id != NULL && runtime->context != NULL && token_frees == 0);
    fail_token_free = 0;
    assert(dfurma_runtime_close(runtime) == 0);
    assert(token_frees == 1);
}

static void test_control_send_recv_retains_ambiguous_posts_and_rejects_bad_ranges(void)
{
    for (int receive = 0; receive <= 1; receive++) {
        for (int mode = 0; mode <= 2; mode++) {
            struct fixture f;
            setup(&f);
            post_mode = mode;
            dfurma_wr_t *wr = NULL;
            int result = receive ?
                dfurma_post_control_recv(&f.jetty, &f.local, 0, 8, 0xabcdef, &wr) :
                dfurma_post_control_send(&f.jetty, &f.target, &f.local, 0, 8, 0xabcdef, &wr);
            assert((result == 0) == (mode == 0));
            if (mode == 1) {
                assert(wr == NULL && f.runtime.outstanding_wr_count == 0);
            } else {
                assert(wr != NULL && f.runtime.outstanding_wr_count == 1);
                assert(f.local.outstanding_wr_count == 1 && f.jetty.outstanding_wr_count == 1);
                assert(f.target.outstanding_wr_count == (receive ? 0U : 1U));
                assert(dfurma_segment_delete(&f.local) == -EBUSY);
                dfurma_wr_complete(wr);
                assert(f.runtime.outstanding_wr_count == 0 && f.local.outstanding_wr_count == 0);
            }
            assert(dfurma_post_control_send(&f.jetty, &f.target, &f.local, 0, 4097, 0, &wr) == -EINVAL);
            assert(wr == NULL);
            assert(dfurma_post_control_recv(&f.jetty, &f.local, 30, 8, 0, &wr) == -EINVAL);
            assert(wr == NULL);
            f.jetty.jetty_error = 1;
            assert(dfurma_post_control_recv(&f.jetty, &f.local, 0, 8, 0, &wr) == -ESHUTDOWN);
        }
    }
}

static void test_control_unused_receives_require_successful_native_destruction(void)
{
    for (int failure = 0; failure <= 2; failure++) {
        struct fixture f;
        urma_jfr_t jfr = {0};
        dfurma_wr_t *wr = NULL;
        setup(&f);
        destroy_failure = failure;
        destroyed_jetty = destroyed_jfr = 0;
        f.jetty.jfr = &jfr;
        assert(dfurma_post_control_recv(&f.jetty, &f.local, 0, 8, 0xabcdef, &wr) == 0);
        assert(f.jetty.control_recv_wr_count == 1);
        assert(dfurma_control_destroy_recv_endpoint(&f.jetty) == -EBUSY);
        f.jetty.jetty_error = f.jetty.jfr_error = 1;
        assert(dfurma_control_destroy_recv_endpoint(&f.jetty) == -EBUSY); /* target */
        f.jetty.target_count = 0;
        f.jetty.outstanding_wr_count++; /* non-RECV work must block destroy */
        assert(dfurma_control_destroy_recv_endpoint(&f.jetty) == -EBUSY);
        f.jetty.outstanding_wr_count--;
        assert(destroyed_jetty == 0 && destroyed_jfr == 0);
        int result = dfurma_control_destroy_recv_endpoint(&f.jetty);
        assert((result == 0) == (failure == 0));
        /* Even successful native destruction must not free the backing/WR. */
        assert(f.runtime.outstanding_wr_count == 1 && f.local.outstanding_wr_count == 1);
        assert(f.jetty.control_recv_wr_count == 1 && f.jetty.free_wr == &f.arena[1]);
        if (failure == 0) {
            assert(f.jetty.jetty == NULL && f.jetty.jfr == NULL);
            assert(destroyed_jetty == 1 && destroyed_jfr == 1);
            dfurma_wr_complete(wr);
            assert(f.jetty.control_recv_wr_count == 0 && f.runtime.outstanding_wr_count == 0);
        } else {
            assert(f.jetty.jfr == &jfr);
            assert((f.jetty.jetty == NULL) == (failure == 2));
            /* No retirement is permitted on failure. Fixture is process-local. */
        }
    }
    destroy_failure = 0;
}

int main(void)
{
    test_control_unused_receives_require_successful_native_destruction();
    test_control_send_recv_retains_ambiguous_posts_and_rejects_bad_ranges();
    test_descriptor_validation();
    test_read_ownership_and_retryable_unimport();
    test_read_preflight();
    test_failed_and_ambiguous_post();
    test_source_to_read_roundtrip_and_separate_release();
    test_source_export_rejects_unrepresented_context();
    test_source_unregister_failure_keeps_token_and_blocks_export();
    test_registration_failure_retains_uncertain_grants();
    test_read_buffer_failure_retains_memory_and_runtime();
    test_allocated_read_buffer_full_lifecycle();
    test_source_register_stage_timings();
    test_shared_token_lives_until_retryable_runtime_close();
    puts("PASS: 14 groups covering control receive destruction, SEND/RECV ownership and source/import/READ retirement");
    return 0;
}
