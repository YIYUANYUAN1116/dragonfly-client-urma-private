# RM READ 离线实现进度

更新时间：2026-09-11。

设计入口：
`/home/yuan/workspace/docs/engineering-lab/dragonfly-urma-adaptation/rm-read/dragonfly-urma-rm-read-design-and-roadmap.md`。

当前没有目标机器。按用户确认先推进可离线验证的代码；设计中的 R0/R1 仍作为启用 native READ 和
接入生产数据路径的门禁。本批属于 R2 的部分基础准备，不代表 R0、R1 或 R2 整体完成。

## 本批实现

- C shim → Rust FFI → Runtime capability 增加 `max_read_size`、`max_write_size`，保持设备返回的字节值；
  不把 SEND `max_msg_size` 或外部“256M”建议当作 READ 能力。
- `urma/read.rs` 提供独立于设备的 READ limit 协商和惰性切片规划。零 limit 关闭 READ，检查两侧
  Segment/allocation 范围、Piece offset、地址溢出、进程可表示长度和单 SGE `u32` 长度。
- `ReadProgress` 跟踪一个 transfer 的保留 post batch、实际 accepted prefix 和未完成 slice。
  per-transfer outstanding 上限约束记账大小，不按全部计划 slice 预分配。
- 取消禁止新 post，但保留尚未返回结果的 post batch 和已接受 WR；post/CQE 错误阻止成功完成，
  已知 WR 继续 drain。重复、未知、长度不匹配 CQE 或不一致的 post 结果不能证明安全 drain。
- 每条 READ 都按独立 CQE 计账，支持乱序完成。全部计划字节成功覆盖与 local drain 分开判断。

## 接入边界

本批没有创建 READ Segment、post native READ、修改 wire version 或发布 RM_READ capability。当前 RM
SEND/RECV 数据路径继续运行；查询到非零 max_read_size 不会自动启用 READ。

`ReadProgress` 是纯记账模块，不是 native owner/RAII guard。后续接入必须满足：

1. 外层 registry 先验证 peer/transfer/Segment generation 和原生 CQE identity，才按 slice index 路由；
2. owner 持有 buffer、imported Segment、PeerTarget 和 native WR，不能因 Rust future/drop 而提前释放；
3. post 前同时取得 shared JFS、per-peer 和 byte permits，并受 shim 最大 post-list 长度约束；
4. owner 串行处理 native post 返回与 CQE，先 commit accepted prefix，再处理对应完成；
5. `locally_drained()` 只表示本 transfer 不会继续 post 且已接受 WR 全部退休，不证明 Parent 撤权；
6. `read_succeeded()` 不允许直接发布 Storage lease；仍需 unimport、ReadDone/Done terminal gate；
7. 真实 READ `completion_len`、error/flush CQE 语义由 probe 确认后才能映射到本模块；
8. 记账进入 uncertain 后不提供猜测式 clear/reset。资源隔离或经验证的 native retirement 由外层负责。

## 离线验证入口

本批结果：

| 检查 | 结果 |
|---|---|
| `cargo fmt --all -- --check`、`git diff --check` | PASS |
| `cc -Wall -Wextra -Werror -fsyntax-only`，使用本地 UMDK include | PASS |
| 直接编译 `read.rs` 纯状态测试 | 12 passed / 0 failed |
| storage feature-on 构建、链接及 `--lib urma::` 测试 | 130 passed / 0 failed，含新增 12 项 |
| native READ / 跨节点 provider / 撤权 | 未执行 |

纯状态测试无需 UMDK、设备或整个 workspace 构建：

```bash
rustc --edition=2021 --test dragonfly-client-storage/src/urma/read.rs \
  -o /tmp/dragonfly-urma-read-unit-tests
/tmp/dragonfly-urma-read-unit-tests
```

完整 URMA 模块测试使用本地 UMDK build：

```bash
env UMDK_INCLUDE_DIR=/home/yuan/workspace/cloud-native/umdk/src/urma/lib/urma/core/include \
  UMDK_LIB_DIR=/home/yuan/workspace/cloud-native/umdk/build-urma/lib/urma/core \
  LD_LIBRARY_PATH=/home/yuan/workspace/cloud-native/umdk/build-urma/lib/urma/core:/home/yuan/workspace/cloud-native/umdk/build-urma/common \
  cargo test --offline -p dragonfly-client-storage --features urma --lib urma::
```

当前 `dragonfly-api` 的 build script 会在 Cargo dependency source 内生成 `src/descriptor.bin`；
只读缓存沙箱会阻断该构建。需要正常可写构建环境，不应为绕过此问题修改业务依赖或关闭 URMA 检查。
该本地 UMDK build 的 `liburma.so` 还依赖 `common/liburma_common.so.SOVERSION`，链接和运行时均需
包含上述 common 路径；只配置 core 路径会出现 `ub_str_to_u*` undefined reference。

## 后续工作

- 外部内存注册、Segment descriptor 和 import/export native wrapper；
- READ operation owner、generation registry 与 native post/flush 集成；
- 双侧 byte budget、`ExportedPieceLease`、BufferReady 和完整取消协议；
- R0/R1 真机 capability、撤权/重用/授权边界验证；
- 通过门禁后再接 file mmap、三类 Piece Storage 和性能验证。

以上均未由本批代码完成；本地编译或纯状态测试不计为真实 provider 验证。
