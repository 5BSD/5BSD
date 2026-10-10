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
struct bsd_runtime_test_ChannelResource;
struct bsd_runtime_test_Collection;
struct bsd_runtime_test_Collections_Check_Result;
struct bsd_runtime_test_Configuration;
struct bsd_runtime_test_DecodeAllocation;
struct bsd_runtime_test_DictionaryEntry;
struct bsd_runtime_test_Empty;
struct bsd_runtime_test_EndpointRequest;
struct bsd_runtime_test_EscapedNames;
struct bsd_runtime_test_Extensible;
typedef uint32_t bsd_runtime_test_Features;
#define bsd_runtime_test_Features_FIRST ((bsd_runtime_test_Features)1ULL)
#define bsd_runtime_test_Features_SECOND ((bsd_runtime_test_Features)2ULL)
struct bsd_runtime_test_Flag;
struct bsd_runtime_test_Flexible_Check_Result;
struct bsd_runtime_test_Flexible_Echo_Result;
struct bsd_runtime_test_Flexible_Ping_Response;
struct bsd_runtime_test_Flexible_Ping_Result;
struct bsd_runtime_test_Large;
struct bsd_runtime_test_Linked;
struct bsd_runtime_test_ManyResources;
typedef uint32_t bsd_runtime_test_Mode;
#define bsd_runtime_test_Mode_OFF ((bsd_runtime_test_Mode)0ULL)
#define bsd_runtime_test_Mode_ON ((bsd_runtime_test_Mode)1ULL)
struct bsd_runtime_test_OptionalEndpointRequest;
struct bsd_runtime_test_OptionalResource;
struct bsd_runtime_test_ReadOnly;
struct bsd_runtime_test_Request;
struct bsd_runtime_test_Resource;
struct bsd_runtime_test_Response;
struct bsd_runtime_test_Selection;
struct bsd_runtime_test_ServerEndpointRequest;
struct bsd_runtime_test_ShapesEchoRequest;
struct bsd_runtime_test_ShapesEchoResponse;
struct bsd_runtime_test_SocketResource;
struct bsd_runtime_test_ChannelResource {
    int fd;
};
struct bsd_runtime_test_Collection {
    int *descriptors;
    size_t descriptors_size;
    struct bsd_runtime_test_DictionaryEntry *entries;
    size_t entries_size;
    uint32_t numbers[3];
    bool *switches;
    size_t switches_size;
    const char *label;
    size_t label_size;
    bool label_present;
    uint32_t *optional_numbers;
    size_t optional_numbers_size;
    bool optional_numbers_present;
    struct bsd_runtime_test_Linked * chain;
    bsd_runtime_test_Mode mode;
    bsd_runtime_test_Features features;
};
struct bsd_runtime_test_Response {
    const char *text;
    size_t text_size;
};
#define bsd_runtime_test_Collections_Check_Result_response_tag UINT64_C(1)
#define bsd_runtime_test_Collections_Check_Result_err_tag UINT64_C(2)
#define bsd_runtime_test_Collections_Check_Result_unknown_tag UINT64_MAX
struct bsd_runtime_test_Collections_Check_Result {
    uint64_t tag;
    union {
        struct bsd_runtime_test_Response response;
        uint32_t err;
    } value;
};
struct bsd_runtime_test_DictionaryEntry {
    const char *key;
    size_t key_size;
    const char *value;
    size_t value_size;
};
#define bsd_runtime_test_Selection_number_tag UINT64_C(1)
#define bsd_runtime_test_Selection_entry_tag UINT64_C(2)
#define bsd_runtime_test_Selection_unknown_tag UINT64_MAX
struct bsd_runtime_test_Selection {
    uint64_t tag;
    union {
        uint32_t number;
        struct bsd_runtime_test_DictionaryEntry entry;
    } value;
};
struct bsd_runtime_test_Configuration {
    bool has_selection;
    struct bsd_runtime_test_Selection selection;
    bool has_label;
    const char *label;
    size_t label_size;
};
struct bsd_runtime_test_DecodeAllocation {
    const char *prefix;
    size_t prefix_size;
    int fd;
    uint32_t *items;
    size_t items_size;
};
struct bsd_runtime_test_Empty {
    unsigned char unused;
};
struct bsd_runtime_test_EndpointRequest {
    int ep;
};
struct bsd_runtime_test_EscapedNames {
    uint32_t switch_fidl;
    const char *text_fidl;
    size_t text_fidl_size;
    uint32_t text_size;
    uint32_t UpperCase;
};
struct bsd_runtime_test_Extensible {
    bool has_fd;
    int fd;
};
struct bsd_runtime_test_Flag {
    bool flag;
};
#define bsd_runtime_test_Flexible_Check_Result_response_tag UINT64_C(1)
#define bsd_runtime_test_Flexible_Check_Result_err_tag UINT64_C(2)
#define bsd_runtime_test_Flexible_Check_Result_framework_err_tag UINT64_C(3)
#define bsd_runtime_test_Flexible_Check_Result_unknown_tag UINT64_MAX
struct bsd_runtime_test_Flexible_Check_Result {
    uint64_t tag;
    union {
        struct bsd_runtime_test_Response response;
        uint32_t err;
        int32_t framework_err;
    } value;
};
#define bsd_runtime_test_Flexible_Echo_Result_response_tag UINT64_C(1)
#define bsd_runtime_test_Flexible_Echo_Result_framework_err_tag UINT64_C(3)
#define bsd_runtime_test_Flexible_Echo_Result_unknown_tag UINT64_MAX
struct bsd_runtime_test_Flexible_Echo_Result {
    uint64_t tag;
    union {
        struct bsd_runtime_test_Response response;
        int32_t framework_err;
    } value;
};
struct bsd_runtime_test_Flexible_Ping_Response {
    unsigned char unused;
};
#define bsd_runtime_test_Flexible_Ping_Result_response_tag UINT64_C(1)
#define bsd_runtime_test_Flexible_Ping_Result_framework_err_tag UINT64_C(3)
#define bsd_runtime_test_Flexible_Ping_Result_unknown_tag UINT64_MAX
struct bsd_runtime_test_Flexible_Ping_Result {
    uint64_t tag;
    union {
        struct bsd_runtime_test_Flexible_Ping_Response response;
        int32_t framework_err;
    } value;
};
struct bsd_runtime_test_Large {
    uint8_t *bytes;
    size_t bytes_size;
};
struct bsd_runtime_test_Linked {
    uint32_t value;
    struct bsd_runtime_test_Linked * next;
};
struct bsd_runtime_test_ManyResources {
    int *fds;
    size_t fds_size;
};
struct bsd_runtime_test_OptionalEndpointRequest {
    int ep;
};
struct bsd_runtime_test_OptionalResource {
    int fd;
};
struct bsd_runtime_test_ReadOnly {
    int fd;
};
struct bsd_runtime_test_Request {
    const char *text;
    size_t text_size;
};
struct bsd_runtime_test_Resource {
    int fd;
};
struct bsd_runtime_test_ServerEndpointRequest {
    int ep;
};
struct bsd_runtime_test_ShapesEchoRequest {
    uint32_t value;
};
struct bsd_runtime_test_ShapesEchoResponse {
    uint32_t value;
};
struct bsd_runtime_test_SocketResource {
    int fd;
};
struct bsd_runtime_test_AjarSurface_server {
    unsigned char unused;
    void (*unknown_interaction)(void *, uint64_t, bool);
};
int bsd_runtime_test_AjarSurface_bind(struct fidl_bsd_connection *, const struct bsd_runtime_test_AjarSurface_server *, void *);
struct bsd_runtime_test_AjarSurface_events {
    void (*unknown_interaction)(void *, uint64_t);
};
int bsd_runtime_test_AjarSurface_bind_events(struct fidl_bsd_connection *, const struct bsd_runtime_test_AjarSurface_events *, void *);
struct bsd_runtime_test_ClosedSurface_server {
    unsigned char unused;
};
int bsd_runtime_test_ClosedSurface_bind(struct fidl_bsd_connection *, const struct bsd_runtime_test_ClosedSurface_server *, void *);
struct bsd_runtime_test_Collections_server {
    void (*Echo)(void *, struct fidl_bsd_connection *, struct fidl_bsd_request *, struct bsd_runtime_test_Collection *);
    void (*Configure)(void *, struct fidl_bsd_connection *, struct fidl_bsd_request *, struct bsd_runtime_test_Configuration *);
    void (*Check)(void *, struct fidl_bsd_connection *, struct fidl_bsd_request *, struct bsd_runtime_test_Request *);
};
int bsd_runtime_test_Collections_bind(struct fidl_bsd_connection *, const struct bsd_runtime_test_Collections_server *, void *);
typedef void (*bsd_runtime_test_Collections_Echo_callback)(void *, int, struct bsd_runtime_test_Collection *);
int bsd_runtime_test_Collections_Echo(struct fidl_bsd_connection *, const struct bsd_runtime_test_Collection *, bsd_runtime_test_Collections_Echo_callback, void *, uint32_t *);
int bsd_runtime_test_Collections_Echo_reply(struct fidl_bsd_connection *, struct fidl_bsd_request *, const struct bsd_runtime_test_Collection *);
typedef void (*bsd_runtime_test_Collections_Configure_callback)(void *, int, struct bsd_runtime_test_Configuration *);
int bsd_runtime_test_Collections_Configure(struct fidl_bsd_connection *, const struct bsd_runtime_test_Configuration *, bsd_runtime_test_Collections_Configure_callback, void *, uint32_t *);
int bsd_runtime_test_Collections_Configure_reply(struct fidl_bsd_connection *, struct fidl_bsd_request *, const struct bsd_runtime_test_Configuration *);
typedef void (*bsd_runtime_test_Collections_Check_callback)(void *, int, struct bsd_runtime_test_Collections_Check_Result *);
int bsd_runtime_test_Collections_Check(struct fidl_bsd_connection *, const struct bsd_runtime_test_Request *, bsd_runtime_test_Collections_Check_callback, void *, uint32_t *);
int bsd_runtime_test_Collections_Check_reply(struct fidl_bsd_connection *, struct fidl_bsd_request *, const struct bsd_runtime_test_Collections_Check_Result *);
struct bsd_runtime_test_EndpointExchange_server {
    void (*RoundTrip)(void *, struct fidl_bsd_connection *, struct fidl_bsd_request *, struct bsd_runtime_test_EndpointRequest *);
};
int bsd_runtime_test_EndpointExchange_bind(struct fidl_bsd_connection *, const struct bsd_runtime_test_EndpointExchange_server *, void *);
typedef void (*bsd_runtime_test_EndpointExchange_RoundTrip_callback)(void *, int, struct bsd_runtime_test_EndpointRequest *);
int bsd_runtime_test_EndpointExchange_RoundTrip(struct fidl_bsd_connection *, const struct bsd_runtime_test_EndpointRequest *, bsd_runtime_test_EndpointExchange_RoundTrip_callback, void *, uint32_t *);
int bsd_runtime_test_EndpointExchange_RoundTrip_reply(struct fidl_bsd_connection *, struct fidl_bsd_request *, const struct bsd_runtime_test_EndpointRequest *);
struct bsd_runtime_test_Flexible_server {
    void (*Ping)(void *, struct fidl_bsd_connection *, struct fidl_bsd_request *, struct fidl_bsd_empty *);
    void (*Echo)(void *, struct fidl_bsd_connection *, struct fidl_bsd_request *, struct bsd_runtime_test_Request *);
    void (*Check)(void *, struct fidl_bsd_connection *, struct fidl_bsd_request *, struct bsd_runtime_test_Request *);
    void (*Note)(void *, struct fidl_bsd_connection *, struct fidl_bsd_request *, struct bsd_runtime_test_Request *);
    void (*StrictPing)(void *, struct fidl_bsd_connection *, struct fidl_bsd_request *, struct fidl_bsd_empty *);
    void (*unknown_interaction)(void *, uint64_t, bool);
};
int bsd_runtime_test_Flexible_bind(struct fidl_bsd_connection *, const struct bsd_runtime_test_Flexible_server *, void *);
typedef void (*bsd_runtime_test_Flexible_Ping_callback)(void *, int, struct bsd_runtime_test_Flexible_Ping_Result *);
int bsd_runtime_test_Flexible_Ping(struct fidl_bsd_connection *, const struct fidl_bsd_empty *, bsd_runtime_test_Flexible_Ping_callback, void *, uint32_t *);
int bsd_runtime_test_Flexible_Ping_reply(struct fidl_bsd_connection *, struct fidl_bsd_request *, const struct bsd_runtime_test_Flexible_Ping_Result *);
typedef void (*bsd_runtime_test_Flexible_Echo_callback)(void *, int, struct bsd_runtime_test_Flexible_Echo_Result *);
int bsd_runtime_test_Flexible_Echo(struct fidl_bsd_connection *, const struct bsd_runtime_test_Request *, bsd_runtime_test_Flexible_Echo_callback, void *, uint32_t *);
int bsd_runtime_test_Flexible_Echo_reply(struct fidl_bsd_connection *, struct fidl_bsd_request *, const struct bsd_runtime_test_Flexible_Echo_Result *);
typedef void (*bsd_runtime_test_Flexible_Check_callback)(void *, int, struct bsd_runtime_test_Flexible_Check_Result *);
int bsd_runtime_test_Flexible_Check(struct fidl_bsd_connection *, const struct bsd_runtime_test_Request *, bsd_runtime_test_Flexible_Check_callback, void *, uint32_t *);
int bsd_runtime_test_Flexible_Check_reply(struct fidl_bsd_connection *, struct fidl_bsd_request *, const struct bsd_runtime_test_Flexible_Check_Result *);
int bsd_runtime_test_Flexible_Note(struct fidl_bsd_connection *, const struct bsd_runtime_test_Request *);
int bsd_runtime_test_Flexible_Changed(struct fidl_bsd_connection *, const struct bsd_runtime_test_Response *);
typedef void (*bsd_runtime_test_Flexible_StrictPing_callback)(void *, int, struct fidl_bsd_empty *);
int bsd_runtime_test_Flexible_StrictPing(struct fidl_bsd_connection *, const struct fidl_bsd_empty *, bsd_runtime_test_Flexible_StrictPing_callback, void *, uint32_t *);
int bsd_runtime_test_Flexible_StrictPing_reply(struct fidl_bsd_connection *, struct fidl_bsd_request *, const struct fidl_bsd_empty *);
struct bsd_runtime_test_Flexible_events {
    void (*Changed)(void *, struct bsd_runtime_test_Response *);
    void (*unknown_interaction)(void *, uint64_t);
};
int bsd_runtime_test_Flexible_bind_events(struct fidl_bsd_connection *, const struct bsd_runtime_test_Flexible_events *, void *);
struct bsd_runtime_test_Naming_server {
    void (*RoundTrip)(void *, struct fidl_bsd_connection *, struct fidl_bsd_request *, struct bsd_runtime_test_EscapedNames *);
};
int bsd_runtime_test_Naming_bind(struct fidl_bsd_connection *, const struct bsd_runtime_test_Naming_server *, void *);
typedef void (*bsd_runtime_test_Naming_RoundTrip_callback)(void *, int, struct bsd_runtime_test_EscapedNames *);
int bsd_runtime_test_Naming_RoundTrip(struct fidl_bsd_connection *, const struct bsd_runtime_test_EscapedNames *, bsd_runtime_test_Naming_RoundTrip_callback, void *, uint32_t *);
int bsd_runtime_test_Naming_RoundTrip_reply(struct fidl_bsd_connection *, struct fidl_bsd_request *, const struct bsd_runtime_test_EscapedNames *);
struct bsd_runtime_test_OpenSurface_server {
    unsigned char unused;
    void (*unknown_interaction)(void *, uint64_t, bool);
};
int bsd_runtime_test_OpenSurface_bind(struct fidl_bsd_connection *, const struct bsd_runtime_test_OpenSurface_server *, void *);
struct bsd_runtime_test_OpenSurface_events {
    void (*unknown_interaction)(void *, uint64_t);
};
int bsd_runtime_test_OpenSurface_bind_events(struct fidl_bsd_connection *, const struct bsd_runtime_test_OpenSurface_events *, void *);
struct bsd_runtime_test_Service_server {
    void (*RoundTrip)(void *, struct fidl_bsd_connection *, struct fidl_bsd_request *, struct bsd_runtime_test_Request *);
    void (*Take)(void *, struct fidl_bsd_connection *, struct fidl_bsd_request *, struct bsd_runtime_test_ReadOnly *);
    void (*Notify)(void *, struct fidl_bsd_connection *, struct fidl_bsd_request *, struct bsd_runtime_test_Request *);
};
int bsd_runtime_test_Service_bind(struct fidl_bsd_connection *, const struct bsd_runtime_test_Service_server *, void *);
typedef void (*bsd_runtime_test_Service_RoundTrip_callback)(void *, int, struct bsd_runtime_test_Response *);
int bsd_runtime_test_Service_RoundTrip(struct fidl_bsd_connection *, const struct bsd_runtime_test_Request *, bsd_runtime_test_Service_RoundTrip_callback, void *, uint32_t *);
int bsd_runtime_test_Service_RoundTrip_reply(struct fidl_bsd_connection *, struct fidl_bsd_request *, const struct bsd_runtime_test_Response *);
typedef void (*bsd_runtime_test_Service_Take_callback)(void *, int, struct bsd_runtime_test_Response *);
int bsd_runtime_test_Service_Take(struct fidl_bsd_connection *, const struct bsd_runtime_test_ReadOnly *, bsd_runtime_test_Service_Take_callback, void *, uint32_t *);
int bsd_runtime_test_Service_Take_reply(struct fidl_bsd_connection *, struct fidl_bsd_request *, const struct bsd_runtime_test_Response *);
int bsd_runtime_test_Service_Notify(struct fidl_bsd_connection *, const struct bsd_runtime_test_Request *);
int bsd_runtime_test_Service_Changed(struct fidl_bsd_connection *, const struct bsd_runtime_test_Response *);
struct bsd_runtime_test_Service_events {
    void (*Changed)(void *, struct bsd_runtime_test_Response *);
};
int bsd_runtime_test_Service_bind_events(struct fidl_bsd_connection *, const struct bsd_runtime_test_Service_events *, void *);
struct bsd_runtime_test_Shapes_server {
    void (*Ping)(void *, struct fidl_bsd_connection *, struct fidl_bsd_request *, struct fidl_bsd_empty *);
    void (*Echo)(void *, struct fidl_bsd_connection *, struct fidl_bsd_request *, struct bsd_runtime_test_ShapesEchoRequest *);
};
int bsd_runtime_test_Shapes_bind(struct fidl_bsd_connection *, const struct bsd_runtime_test_Shapes_server *, void *);
typedef void (*bsd_runtime_test_Shapes_Ping_callback)(void *, int, struct fidl_bsd_empty *);
int bsd_runtime_test_Shapes_Ping(struct fidl_bsd_connection *, const struct fidl_bsd_empty *, bsd_runtime_test_Shapes_Ping_callback, void *, uint32_t *);
int bsd_runtime_test_Shapes_Ping_reply(struct fidl_bsd_connection *, struct fidl_bsd_request *, const struct fidl_bsd_empty *);
typedef void (*bsd_runtime_test_Shapes_Echo_callback)(void *, int, struct bsd_runtime_test_ShapesEchoResponse *);
int bsd_runtime_test_Shapes_Echo(struct fidl_bsd_connection *, const struct bsd_runtime_test_ShapesEchoRequest *, bsd_runtime_test_Shapes_Echo_callback, void *, uint32_t *);
int bsd_runtime_test_Shapes_Echo_reply(struct fidl_bsd_connection *, struct fidl_bsd_request *, const struct bsd_runtime_test_ShapesEchoResponse *);
#ifdef __cplusplus
}
#endif
