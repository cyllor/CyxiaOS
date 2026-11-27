# V0.20 G1 初始镜像候选

这个 512 MiB 稀疏 raw 夹具采用 D1 的规范参考位置，绑定仓库现有签名 scratch 配置和测试主体 `1:1`。
初始超级块为两份相同的 v1 记录，BootEpoch 为 0，持久收据为空，FileStreamIndex 未分配流。
空业务根采用当前格式化夹具的 128 字节目录大小。八个系统对象占用 151 块，另外分配一个根目录块。
四个新增对象仅使用 D1.5 信封。所有待冻结字段及续块保持全零。

```sh
python3 -B tools/v020_g1_genesis.py generate /tmp/cyx-g1-genesis.raw
python3 -B tools/v020_g1_genesis.py verify /tmp/cyx-g1-genesis.raw
python3 -B -m unittest -v tools.test_v020_g1_genesis
cargo test --locked -p cyxia-kernel-core --test media_staging signed_unified_genesis_matches_the_independent_full_image_vector -- --exact
```

生成器创建新文件，验证器只读检查所有块和镜像的固定 SHA-256。Rust 测试独立调用现有签名
scratch 格式化器，核对全部字节的相同摘要，再检查只读挂载收据、分配布局和签名配置绑定。
这里的根目录初值、使用中的测试主体和签名夹具均属候选输入。D7 字节精确冻结仍须设计权威审定非空
目录载荷、槽描述页和镜像格式、请求记录与生产配置。
[G1 介质冻结件](../../docs/design/v0.20-g1-media-freeze.md)
