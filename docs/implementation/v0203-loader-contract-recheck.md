# V0.20.3 静态加载器合同与宿主可移植性复审

日期：2026-11-26。

本次保留 FullOsV3 的逐文件 SHA-256 审核门，只把三个经过完整差异复核的格式化文件更新到准确源码身份。未改变 ELF 布局、W^X、地址与页数约束、分配策略或发布权限；不构成原生 COSMIC 运行验收。

## 对照身份与结论

- 既有已审核版本：`e5d8306990013dda5de55266555be39c7f8495c2`。
- 当前审核基线：`89f87ec7d480cd2cfc5851cecc079da5b3786459`。
- 四个旧 SHA 均与前一版本完整文件字节匹配；当前 `executable.rs` 字节未变，保留原 SHA。
- `user_layout.rs` 的全部差异只在测试中换行/缩进。
- `image.rs` 的全部差异只展开两个等价 `match` 的格式。
- `exec_memory.rs` 的全部差异仅调整 `use` 顺序、换行，并为相同 match 表达式加等价块。实际布局、解析、准入、分配与执行路径没有变化。
- 不使用任意新哈希掩盖语义变更。后续任何未审核的源码字节变化仍被 `loader_contract()` 拒绝；`test_reviewed_production_contract_rejects_drift` 本轮通过。

| 文件 | 既有已审核 SHA-256 | 当前基线 SHA-256 |
|---|---|---|
| `crates/contracts/src/user_layout.rs` | `10edd3b77ee0896563fef4f19662d2b366b729198f35adb2982eb8fb812365f3` | `8c97945de3ce0f7f517354cfb7455d0c7affb39fe7a3c17d6691468400d244e7` |
| `crates/contracts/src/image.rs` | `c6440043f43d5fea3a676adf30d37b2750936ef5782bbcdcd6b87d1907fce639` | `8344a288a3af4a68105688d938d91269d1e8002623763ab2702d2d9d6ae9706a` |
| `crates/posix/src/executable.rs` | `0a2310be332d66a2c1e06ededc28c06fe41c4949db686b35f53e7ccd53e2b5e7` | `0a2310be332d66a2c1e06ededc28c06fe41c4949db686b35f53e7ccd53e2b5e7` |
| `kernel/src/desktop/memory/exec_memory.rs` | `824b5132ea3f215e8ace9aacf848ca74e0d9603cb71569a0afcb4dde6fab91bc` | `23c613788a9978ab07aaa124f763fc6353b19e3413268f6ff08ab19b5db3c3a4` |

## 有界宿主兼容修复

五个测试文件的六处 `TemporaryDirectory` 不再硬编码 macOS 的 `/private/tmp`，使用宿主默认临时目录并立即 `Path.resolve()`。临时目录生命周期和清理语义不变；canonical 路径保留被测工具的反符号链接约束。另有三个测试中的 `/private/tmp` 只是协议样本或负向路径字面量，未修改。

真实目录复制随后暴露两个 assembler 的 Darwin 专用 `cp -cRp`。现按平台保留 Darwin 的原克隆优化，其他 POSIX 宿主使用 `cp -Rp`。递归及元数据保留、现有完整性复核、源/目标隔离、失败清理与原子重命名发布逻辑均未改动。验证使用真实 Linux `/bin/cp`，没有 mock/skip 替代。

## 实际验证

首次全 tools 运行保留失败日志：2180 项，38 failures、171 errors、33 skipped。其中 156 条诊断直接源于旧 loader pin；另四条 publication 故障注入未触发在 pin 修复后消失。不得将这些级联诊断算作 160 个独立产品缺陷。

第一次有界复验：41 项，4 errors，全部为 `/bin/cp` 不支持 `-c`；日志 `v0203-loader-portable-green.log`。

复制兼容修复后同一组精确复验：**41 项，0 failures、0 errors、0 skipped，exit 0**；耗时 20.444 秒。包含恶意 ELF/W^X/TLS/地址边界、源码 drift 拒绝、settings publication 的真实故障注入、原始目录字节/权限保留与输出拒绝，以及合成 SDK/源码闭包测试。仅宿主验证，不编译或运行真实桌面程序。

最终日志：`v0203-loader-portable-final.log`；SHA-256：`fc6003b88d33ab9989fcb8f45f7dc5e853d30afad0bcb78b2c9aff0fe9301f64`。

```sh
PYTHONPATH=.:tools RUSTUP_TOOLCHAIN=1.95.0 PATH=/home/agent/.cargo/bin:$PATH \
python -m unittest -v \
  tools.test_cosmic_notifications_elf \
  tools.test_install_cosmic_settings_linux_v1 \
  tools.test_assemble_cosmic_optional_workspace_v1 \
  tools.test_assemble_cosmic_workspace_applets_v1 \
  tools.test_cosmic_applet_object_profile_v1 \
  tools.test_cosmic_workspace_result_v1 \
  tools.test_cosmic_workspace_applets_v1.WorkspaceAppletContract.test_additional_sdk_rejects_tampered_receipts_archives_and_wrong_isa \
  tools.test_cosmic_workspace_applets_v1.WorkspaceAppletContract.test_export_checks_real_modes_without_assuming_digest_records_have_modes
```

全 tools 未在本轮重跑。缺少真实历史归档、macOS 宿主绑定的构建输入、受限 AF_UNIX 与 v16 schema 演进等独立问题继续留在总台账，不因这 41 项通过而关闭。未改 AF_UNIX 测试或加入绕过性 skip。

## 完整源码对照

下列为上述两个准确提交、四个审核文件的完整 `git diff`，用于复核本次身份更新限于无语义格式变化。

```diff
diff --git a/crates/contracts/src/image.rs b/crates/contracts/src/image.rs
index b741ff8..dc55623 100644
--- a/crates/contracts/src/image.rs
+++ b/crates/contracts/src/image.rs
@@ -8,9 +8,15 @@ pub enum ImageAbi {

 impl ImageAbi {
     pub const fn machine(self) -> u16 {
-        match self { Self::Aarch64 => 183, Self::X86_64 => 62 }
+        match self {
+            Self::Aarch64 => 183,
+            Self::X86_64 => 62,
+        }
     }
     pub const fn entry_alignment(self) -> u64 {
-        match self { Self::Aarch64 => 4, Self::X86_64 => 1 }
+        match self {
+            Self::Aarch64 => 4,
+            Self::X86_64 => 1,
+        }
     }
 }
diff --git a/crates/contracts/src/user_layout.rs b/crates/contracts/src/user_layout.rs
index 6a032d6..df5fdc5 100644
--- a/crates/contracts/src/user_layout.rs
+++ b/crates/contracts/src/user_layout.rs
@@ -75,12 +75,22 @@ mod tests {

     #[test]
     fn full_os_image_heap_stack_and_existing_shared_window_do_not_alias() {
-        for profile in [ImageProfile::FullOsV1, ImageProfile::FullOsV2, ImageProfile::FullOsV3] {
+        for profile in [
+            ImageProfile::FullOsV1,
+            ImageProfile::FullOsV2,
+            ImageProfile::FullOsV3,
+        ] {
             let layout = profile.layout();
             let regions = [
                 (layout.image_base, layout.image_end),
-                (layout.stack_base, layout.stack_base + layout.stack_pages as u64 * 4096),
-                (layout.heap_base, layout.heap_base + layout.heap_pages as u64 * 4096),
+                (
+                    layout.stack_base,
+                    layout.stack_base + layout.stack_pages as u64 * 4096,
+                ),
+                (
+                    layout.heap_base,
+                    layout.heap_base + layout.heap_pages as u64 * 4096,
+                ),
                 (0x0600_0000, 0x0700_0000),
             ];
             for (i, &(start, end)) in regions.iter().enumerate() {
@@ -98,14 +108,20 @@ mod tests {
             let leaf_tables = layout.image_pages() / 512 + layout.heap_pages / 512 + 8 + 1;
             assert!(leaf_tables + 8 < 128);
             let stack_end = layout.stack_base + layout.stack_pages as u64 * 4096;
-            assert!(layout.heap_base > stack_end || layout.heap_base + layout.heap_pages as u64 * 4096 < layout.stack_base);
+            assert!(
+                layout.heap_base > stack_end
+                    || layout.heap_base + layout.heap_pages as u64 * 4096 < layout.stack_base
+            );
         }
     }

     #[test]
     fn legacy_profile_retains_historical_image_and_stack_contract() {
         let layout = ImageProfile::Legacy.layout();
-        assert_eq!((layout.image_base, layout.image_end), (0x01000000, 0x02000000));
+        assert_eq!(
+            (layout.image_base, layout.image_end),
+            (0x01000000, 0x02000000)
+        );
         assert_eq!((layout.stack_base, layout.stack_pages), (0x03000000, 64));
         assert_eq!(layout.exec_pool_pages, 4096);
     }
@@ -115,9 +131,18 @@ mod tests {
         let previous = ImageProfile::FullOsV2.layout();
         let layout = ImageProfile::FullOsV3.layout();
         assert_eq!(ImageProfile::FullOsV3.name(), "full-os-v3");
-        assert_eq!(layout, ImageLayout { heap_pages: 16384, ..previous });
+        assert_eq!(
+            layout,
+            ImageLayout {
+                heap_pages: 16384,
+                ..previous
+            }
+        );
         assert_eq!(layout.heap_base, 0x0c00_0000);
-        assert_eq!(layout.heap_base + layout.heap_pages as u64 * 4096, 0x1000_0000);
+        assert_eq!(
+            layout.heap_base + layout.heap_pages as u64 * 4096,
+            0x1000_0000
+        );
         assert_eq!(ImageProfile::FullOsV1.layout().heap_pages, 4096);
         assert_eq!(previous.heap_pages, 8192);
     }
diff --git a/kernel/src/desktop/memory/exec_memory.rs b/kernel/src/desktop/memory/exec_memory.rs
index 05a9266..0d0b25a 100644
--- a/kernel/src/desktop/memory/exec_memory.rs
+++ b/kernel/src/desktop/memory/exec_memory.rs
@@ -5,8 +5,8 @@ use core::sync::atomic::{AtomicU64, Ordering};
 use cyxia_ai_runtime::accounting::Attempt;
 #[cfg(target_arch = "aarch64")]
 use cyxia_contracts::BootInfo;
-use cyxia_contracts::{PageCount, RedemptionId};
 use cyxia_contracts::user_layout::ImageProfile;
+use cyxia_contracts::{PageCount, RedemptionId};
 use cyxia_kernel_core::grants::{AuthorizedGrantRequest, GrantLedger, Owner, ReleaseReceipt};
 use cyxia_posix::{
     Errno,
@@ -145,12 +145,19 @@ impl ExecMemory {
         }
         attempt.proposed(match PROFILE {
             ImageProfile::Legacy => 8195,
-            ImageProfile::FullOsV1 | ImageProfile::FullOsV2 | ImageProfile::FullOsV3 => cyxia_ai_runtime::FULL_OS_EXEC_MODEL_ID,
+            ImageProfile::FullOsV1 | ImageProfile::FullOsV2 | ImageProfile::FullOsV3 => {
+                cyxia_ai_runtime::FULL_OS_EXEC_MODEL_ID
+            }
         });
         let (allowed, model) = match PROFILE {
-            ImageProfile::Legacy => cyxia_ai_runtime::executable_memory_policy(PAGES as u32, count as u32),
-            ImageProfile::FullOsV1 | ImageProfile::FullOsV2 | ImageProfile::FullOsV3 => cyxia_ai_runtime::full_os_executable_memory_policy(PAGES as u32, count as u32),
-        }.map_err(|_| Errno::Io)?;
+            ImageProfile::Legacy => {
+                cyxia_ai_runtime::executable_memory_policy(PAGES as u32, count as u32)
+            }
+            ImageProfile::FullOsV1 | ImageProfile::FullOsV2 | ImageProfile::FullOsV3 => {
+                cyxia_ai_runtime::full_os_executable_memory_policy(PAGES as u32, count as u32)
+            }
+        }
+        .map_err(|_| Errno::Io)?;
         attempt.decided(allowed, model);
         if !allowed {
             return Err(Errno::Nomem);
```
