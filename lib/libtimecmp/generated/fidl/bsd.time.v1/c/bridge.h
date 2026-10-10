// Generated private C++ conversions for the C ABI; do not edit.
#pragma once
#include <fidl/bsd/c_bridge.h>
#include <fidl/bsd.time.v1/cpp/natural_types.h>
#include <fidl/bsd.time.v1/c/bsd.h>
namespace fidl::bsd::generated {
inline ::bsd_time_v1::Delta FromC(const bsd_time_v1_Delta*, fidl::bsd::CEncodeBudget&, size_t);
inline void ToC(::bsd_time_v1::Delta&, bsd_time_v1_Delta&, fidl::bsd::CViewArena&, size_t);
inline ::bsd_time_v1::ProtocolInfo FromC(const bsd_time_v1_ProtocolInfo*, fidl::bsd::CEncodeBudget&, size_t);
inline void ToC(::bsd_time_v1::ProtocolInfo&, bsd_time_v1_ProtocolInfo&, fidl::bsd::CViewArena&, size_t);
inline ::bsd_time_v1::TimeAdjustResult FromC(const bsd_time_v1_Time_Adjust_Result*, fidl::bsd::CEncodeBudget&, size_t);
inline void ToC(::bsd_time_v1::TimeAdjustResult&, bsd_time_v1_Time_Adjust_Result&, fidl::bsd::CViewArena&, size_t);
inline ::bsd_time_v1::TimeGetResult FromC(const bsd_time_v1_Time_Get_Result*, fidl::bsd::CEncodeBudget&, size_t);
inline void ToC(::bsd_time_v1::TimeGetResult&, bsd_time_v1_Time_Get_Result&, fidl::bsd::CViewArena&, size_t);
inline ::bsd_time_v1::TimeSetResponse FromC(const bsd_time_v1_Time_Set_Response*, fidl::bsd::CEncodeBudget&, size_t);
inline void ToC(::bsd_time_v1::TimeSetResponse&, bsd_time_v1_Time_Set_Response&, fidl::bsd::CViewArena&, size_t);
inline ::bsd_time_v1::TimeSetResult FromC(const bsd_time_v1_Time_Set_Result*, fidl::bsd::CEncodeBudget&, size_t);
inline void ToC(::bsd_time_v1::TimeSetResult&, bsd_time_v1_Time_Set_Result&, fidl::bsd::CViewArena&, size_t);
inline ::bsd_time_v1::Timestamp FromC(const bsd_time_v1_Timestamp*, fidl::bsd::CEncodeBudget&, size_t);
inline void ToC(::bsd_time_v1::Timestamp&, bsd_time_v1_Timestamp&, fidl::bsd::CViewArena&, size_t);
inline ::bsd_time_v1::Delta FromC(const bsd_time_v1_Delta* input, fidl::bsd::CEncodeBudget& budget, size_t depth) {
if (!input) throw std::system_error(EINVAL, std::generic_category());
budget.Enter(depth);
auto value = fidl::internal::DefaultConstructPossiblyInvalidObject<::bsd_time_v1::Delta>::Make();
value.seconds() = input->seconds;
value.microseconds() = input->microseconds;
return value;
}
inline ::bsd_time_v1::Delta FromC(const bsd_time_v1_Delta* input) { fidl::bsd::CEncodeBudget budget; return FromC(input, budget, 0); }
inline void ToC(::bsd_time_v1::Delta& value, bsd_time_v1_Delta& data, fidl::bsd::CViewArena& arena, size_t depth) {
if (depth > 64) throw std::system_error(EINVAL, std::generic_category());
data.seconds = value.seconds();
data.microseconds = value.microseconds();
}
struct View_bsd_time_v1_Delta {
bsd_time_v1_Delta data{};
fidl::bsd::CViewArena arena;
explicit View_bsd_time_v1_Delta(::bsd_time_v1::Delta& value) { ToC(value, data, arena, 0); }
};
inline ::bsd_time_v1::ProtocolInfo FromC(const bsd_time_v1_ProtocolInfo* input, fidl::bsd::CEncodeBudget& budget, size_t depth) {
if (!input) throw std::system_error(EINVAL, std::generic_category());
budget.Enter(depth);
auto value = fidl::internal::DefaultConstructPossiblyInvalidObject<::bsd_time_v1::ProtocolInfo>::Make();
value.wire_version() = input->wire_version;
return value;
}
inline ::bsd_time_v1::ProtocolInfo FromC(const bsd_time_v1_ProtocolInfo* input) { fidl::bsd::CEncodeBudget budget; return FromC(input, budget, 0); }
inline void ToC(::bsd_time_v1::ProtocolInfo& value, bsd_time_v1_ProtocolInfo& data, fidl::bsd::CViewArena& arena, size_t depth) {
if (depth > 64) throw std::system_error(EINVAL, std::generic_category());
data.wire_version = value.wire_version();
}
struct View_bsd_time_v1_ProtocolInfo {
bsd_time_v1_ProtocolInfo data{};
fidl::bsd::CViewArena arena;
explicit View_bsd_time_v1_ProtocolInfo(::bsd_time_v1::ProtocolInfo& value) { ToC(value, data, arena, 0); }
};
inline ::bsd_time_v1::TimeAdjustResult FromC(const bsd_time_v1_Time_Adjust_Result* input, fidl::bsd::CEncodeBudget& budget, size_t depth) {
if (!input) throw std::system_error(EINVAL, std::generic_category());
budget.Enter(depth);
auto value = fidl::internal::DefaultConstructPossiblyInvalidObject<::bsd_time_v1::TimeAdjustResult>::Make();
switch (input->tag) {
case 1ULL: {
auto item_1 = fidl::internal::DefaultConstructPossiblyInvalidObject<std::remove_cvref_t<decltype(value.response().value())>>::Make();
item_1 = FromC(&input->value.response, budget, depth+1);
value.response(std::move(item_1)); break;
}
case 2ULL: {
auto item_2 = fidl::internal::DefaultConstructPossiblyInvalidObject<std::remove_cvref_t<decltype(value.err().value())>>::Make();
item_2 = input->value.err;
value.err(std::move(item_2)); break;
}
default: throw std::system_error(EINVAL, std::generic_category());
}
return value;
}
inline ::bsd_time_v1::TimeAdjustResult FromC(const bsd_time_v1_Time_Adjust_Result* input) { fidl::bsd::CEncodeBudget budget; return FromC(input, budget, 0); }
inline void ToC(::bsd_time_v1::TimeAdjustResult& value, bsd_time_v1_Time_Adjust_Result& data, fidl::bsd::CViewArena& arena, size_t depth) {
if (depth > 64) throw std::system_error(EINVAL, std::generic_category());
data.tag = static_cast<uint64_t>(value.Which());
switch (data.tag) {
case 1ULL: {
ToC(value.response().value(), data.value.response, arena, depth+1);
break;
}
case 2ULL: {
data.value.err = value.err().value();
break;
}
default: data.tag = UINT64_MAX; break;
}
}
struct View_bsd_time_v1_Time_Adjust_Result {
bsd_time_v1_Time_Adjust_Result data{};
fidl::bsd::CViewArena arena;
explicit View_bsd_time_v1_Time_Adjust_Result(::bsd_time_v1::TimeAdjustResult& value) { ToC(value, data, arena, 0); }
};
inline ::bsd_time_v1::TimeGetResult FromC(const bsd_time_v1_Time_Get_Result* input, fidl::bsd::CEncodeBudget& budget, size_t depth) {
if (!input) throw std::system_error(EINVAL, std::generic_category());
budget.Enter(depth);
auto value = fidl::internal::DefaultConstructPossiblyInvalidObject<::bsd_time_v1::TimeGetResult>::Make();
switch (input->tag) {
case 1ULL: {
auto item_3 = fidl::internal::DefaultConstructPossiblyInvalidObject<std::remove_cvref_t<decltype(value.response().value())>>::Make();
item_3 = FromC(&input->value.response, budget, depth+1);
value.response(std::move(item_3)); break;
}
case 2ULL: {
auto item_4 = fidl::internal::DefaultConstructPossiblyInvalidObject<std::remove_cvref_t<decltype(value.err().value())>>::Make();
item_4 = input->value.err;
value.err(std::move(item_4)); break;
}
default: throw std::system_error(EINVAL, std::generic_category());
}
return value;
}
inline ::bsd_time_v1::TimeGetResult FromC(const bsd_time_v1_Time_Get_Result* input) { fidl::bsd::CEncodeBudget budget; return FromC(input, budget, 0); }
inline void ToC(::bsd_time_v1::TimeGetResult& value, bsd_time_v1_Time_Get_Result& data, fidl::bsd::CViewArena& arena, size_t depth) {
if (depth > 64) throw std::system_error(EINVAL, std::generic_category());
data.tag = static_cast<uint64_t>(value.Which());
switch (data.tag) {
case 1ULL: {
ToC(value.response().value(), data.value.response, arena, depth+1);
break;
}
case 2ULL: {
data.value.err = value.err().value();
break;
}
default: data.tag = UINT64_MAX; break;
}
}
struct View_bsd_time_v1_Time_Get_Result {
bsd_time_v1_Time_Get_Result data{};
fidl::bsd::CViewArena arena;
explicit View_bsd_time_v1_Time_Get_Result(::bsd_time_v1::TimeGetResult& value) { ToC(value, data, arena, 0); }
};
inline ::bsd_time_v1::TimeSetResponse FromC(const bsd_time_v1_Time_Set_Response* input, fidl::bsd::CEncodeBudget& budget, size_t depth) {
if (!input) throw std::system_error(EINVAL, std::generic_category());
budget.Enter(depth);
auto value = fidl::internal::DefaultConstructPossiblyInvalidObject<::bsd_time_v1::TimeSetResponse>::Make();
return value;
}
inline ::bsd_time_v1::TimeSetResponse FromC(const bsd_time_v1_Time_Set_Response* input) { fidl::bsd::CEncodeBudget budget; return FromC(input, budget, 0); }
inline void ToC(::bsd_time_v1::TimeSetResponse& value, bsd_time_v1_Time_Set_Response& data, fidl::bsd::CViewArena& arena, size_t depth) {
if (depth > 64) throw std::system_error(EINVAL, std::generic_category());
}
struct View_bsd_time_v1_Time_Set_Response {
bsd_time_v1_Time_Set_Response data{};
fidl::bsd::CViewArena arena;
explicit View_bsd_time_v1_Time_Set_Response(::bsd_time_v1::TimeSetResponse& value) { ToC(value, data, arena, 0); }
};
inline ::bsd_time_v1::TimeSetResult FromC(const bsd_time_v1_Time_Set_Result* input, fidl::bsd::CEncodeBudget& budget, size_t depth) {
if (!input) throw std::system_error(EINVAL, std::generic_category());
budget.Enter(depth);
auto value = fidl::internal::DefaultConstructPossiblyInvalidObject<::bsd_time_v1::TimeSetResult>::Make();
switch (input->tag) {
case 1ULL: {
auto item_5 = fidl::internal::DefaultConstructPossiblyInvalidObject<std::remove_cvref_t<decltype(value.response().value())>>::Make();
item_5 = FromC(&input->value.response, budget, depth+1);
value.response(std::move(item_5)); break;
}
case 2ULL: {
auto item_6 = fidl::internal::DefaultConstructPossiblyInvalidObject<std::remove_cvref_t<decltype(value.err().value())>>::Make();
item_6 = input->value.err;
value.err(std::move(item_6)); break;
}
default: throw std::system_error(EINVAL, std::generic_category());
}
return value;
}
inline ::bsd_time_v1::TimeSetResult FromC(const bsd_time_v1_Time_Set_Result* input) { fidl::bsd::CEncodeBudget budget; return FromC(input, budget, 0); }
inline void ToC(::bsd_time_v1::TimeSetResult& value, bsd_time_v1_Time_Set_Result& data, fidl::bsd::CViewArena& arena, size_t depth) {
if (depth > 64) throw std::system_error(EINVAL, std::generic_category());
data.tag = static_cast<uint64_t>(value.Which());
switch (data.tag) {
case 1ULL: {
ToC(value.response().value(), data.value.response, arena, depth+1);
break;
}
case 2ULL: {
data.value.err = value.err().value();
break;
}
default: data.tag = UINT64_MAX; break;
}
}
struct View_bsd_time_v1_Time_Set_Result {
bsd_time_v1_Time_Set_Result data{};
fidl::bsd::CViewArena arena;
explicit View_bsd_time_v1_Time_Set_Result(::bsd_time_v1::TimeSetResult& value) { ToC(value, data, arena, 0); }
};
inline ::bsd_time_v1::Timestamp FromC(const bsd_time_v1_Timestamp* input, fidl::bsd::CEncodeBudget& budget, size_t depth) {
if (!input) throw std::system_error(EINVAL, std::generic_category());
budget.Enter(depth);
auto value = fidl::internal::DefaultConstructPossiblyInvalidObject<::bsd_time_v1::Timestamp>::Make();
value.seconds() = input->seconds;
value.nanoseconds() = input->nanoseconds;
return value;
}
inline ::bsd_time_v1::Timestamp FromC(const bsd_time_v1_Timestamp* input) { fidl::bsd::CEncodeBudget budget; return FromC(input, budget, 0); }
inline void ToC(::bsd_time_v1::Timestamp& value, bsd_time_v1_Timestamp& data, fidl::bsd::CViewArena& arena, size_t depth) {
if (depth > 64) throw std::system_error(EINVAL, std::generic_category());
data.seconds = value.seconds();
data.nanoseconds = value.nanoseconds();
}
struct View_bsd_time_v1_Timestamp {
bsd_time_v1_Timestamp data{};
fidl::bsd::CViewArena arena;
explicit View_bsd_time_v1_Timestamp(::bsd_time_v1::Timestamp& value) { ToC(value, data, arena, 0); }
};
}
