/* Generated C bindings; do not edit. */
#pragma once
#include <fidl/bsd/runtime_c.h>
#include <stdbool.h>
#ifdef __cplusplus
extern "C" {
#endif
/* Outgoing buffers and descriptors are borrowed; descriptors are duplicated.
 * Callback buffers last until return. Take a callback descriptor with
 * fidl_bsd_take_fd() to retain it. Retain request contexts for deferred replies. */
struct bsd_time_v1_Delta;
struct bsd_time_v1_ProtocolInfo;
struct bsd_time_v1_Time_Adjust_Result;
struct bsd_time_v1_Time_Get_Result;
struct bsd_time_v1_Time_Set_Response;
struct bsd_time_v1_Time_Set_Result;
struct bsd_time_v1_Timestamp;
struct bsd_time_v1_Delta {
    int64_t seconds;
    int32_t microseconds;
};
struct bsd_time_v1_ProtocolInfo {
    uint32_t wire_version;
};
#define bsd_time_v1_Time_Adjust_Result_response_tag UINT64_C(1)
#define bsd_time_v1_Time_Adjust_Result_err_tag UINT64_C(2)
#define bsd_time_v1_Time_Adjust_Result_unknown_tag UINT64_MAX
struct bsd_time_v1_Time_Adjust_Result {
    uint64_t tag;
    union {
        struct bsd_time_v1_Delta response;
        uint32_t err;
    } value;
};
struct bsd_time_v1_Timestamp {
    int64_t seconds;
    int32_t nanoseconds;
};
#define bsd_time_v1_Time_Get_Result_response_tag UINT64_C(1)
#define bsd_time_v1_Time_Get_Result_err_tag UINT64_C(2)
#define bsd_time_v1_Time_Get_Result_unknown_tag UINT64_MAX
struct bsd_time_v1_Time_Get_Result {
    uint64_t tag;
    union {
        struct bsd_time_v1_Timestamp response;
        uint32_t err;
    } value;
};
struct bsd_time_v1_Time_Set_Response {
    unsigned char unused;
};
#define bsd_time_v1_Time_Set_Result_response_tag UINT64_C(1)
#define bsd_time_v1_Time_Set_Result_err_tag UINT64_C(2)
#define bsd_time_v1_Time_Set_Result_unknown_tag UINT64_MAX
struct bsd_time_v1_Time_Set_Result {
    uint64_t tag;
    union {
        struct bsd_time_v1_Time_Set_Response response;
        uint32_t err;
    } value;
};
struct bsd_time_v1_Time_server {
    void (*GetProtocolInfo)(void *, struct fidl_bsd_connection *, struct fidl_bsd_request *, struct fidl_bsd_empty *);
    void (*Get)(void *, struct fidl_bsd_connection *, struct fidl_bsd_request *, struct fidl_bsd_empty *);
    void (*Set)(void *, struct fidl_bsd_connection *, struct fidl_bsd_request *, struct bsd_time_v1_Timestamp *);
    void (*Adjust)(void *, struct fidl_bsd_connection *, struct fidl_bsd_request *, struct bsd_time_v1_Delta *);
};
int bsd_time_v1_Time_bind(struct fidl_bsd_connection *, const struct bsd_time_v1_Time_server *, void *);
typedef void (*bsd_time_v1_Time_GetProtocolInfo_callback)(void *, int, struct bsd_time_v1_ProtocolInfo *);
int bsd_time_v1_Time_GetProtocolInfo(struct fidl_bsd_connection *, const struct fidl_bsd_empty *, bsd_time_v1_Time_GetProtocolInfo_callback, void *, uint32_t *);
int bsd_time_v1_Time_GetProtocolInfo_reply(struct fidl_bsd_connection *, struct fidl_bsd_request *, const struct bsd_time_v1_ProtocolInfo *);
typedef void (*bsd_time_v1_Time_Get_callback)(void *, int, struct bsd_time_v1_Time_Get_Result *);
int bsd_time_v1_Time_Get(struct fidl_bsd_connection *, const struct fidl_bsd_empty *, bsd_time_v1_Time_Get_callback, void *, uint32_t *);
int bsd_time_v1_Time_Get_reply(struct fidl_bsd_connection *, struct fidl_bsd_request *, const struct bsd_time_v1_Time_Get_Result *);
typedef void (*bsd_time_v1_Time_Set_callback)(void *, int, struct bsd_time_v1_Time_Set_Result *);
int bsd_time_v1_Time_Set(struct fidl_bsd_connection *, const struct bsd_time_v1_Timestamp *, bsd_time_v1_Time_Set_callback, void *, uint32_t *);
int bsd_time_v1_Time_Set_reply(struct fidl_bsd_connection *, struct fidl_bsd_request *, const struct bsd_time_v1_Time_Set_Result *);
typedef void (*bsd_time_v1_Time_Adjust_callback)(void *, int, struct bsd_time_v1_Time_Adjust_Result *);
int bsd_time_v1_Time_Adjust(struct fidl_bsd_connection *, const struct bsd_time_v1_Delta *, bsd_time_v1_Time_Adjust_callback, void *, uint32_t *);
int bsd_time_v1_Time_Adjust_reply(struct fidl_bsd_connection *, struct fidl_bsd_request *, const struct bsd_time_v1_Time_Adjust_Result *);
#ifdef __cplusplus
}
#endif
