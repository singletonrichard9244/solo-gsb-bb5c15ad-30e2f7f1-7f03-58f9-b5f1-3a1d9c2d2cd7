# verifiable-draw

可验证的公开**分组名额抽签** API：承诺-揭示（commit-reveal）协议 + 基于 SHA-256 拒绝采样的 Fisher-Yates 洗牌，保证中奖顺序**无偏、可复算、可审计**。创建抽签（v3 协议）时用**有序分组** `groups`（组名 + 候选 + 名额）描述抽签结构，承诺同时绑定**分组快照**——组名、候选归属（哪个候选属于哪个组）、名额或组序的任何改动都会使校验失败。揭示后每组使用独立的随机流各自开奖，返回各组完整顺序与中奖者。支持两种熵来源：

- **单 nonce 模式**：调用方揭示一次公共 nonce。
- **多人承诺模式**：创建抽签时声明参与者名单，每人先提交 `SHA-256(secret)` 承诺、再揭示 secret；全部揭示后，服务端按**固定参与者顺序**拼接各人 secret 的哈希作为 nonce。任一方都无法单独左右结果，整条贡献链可审计。

技术栈：Node.js 24 + Fastify 5 + SQLite（Node 内置 `node:sqlite`，零原生依赖）。

## 一键启动（Docker Compose）

```bash
docker compose up --build
```

服务地址：**http://localhost:3000** （端口 `3000`，首次启动自动建表，无需手动迁移；旧版数据库会在启动时自动迁移——v2 迁移为 `draws` 表增加 `protocol_version` / `snapshot_digest` 两列，v3 迁移增加 `groups` 列；既有记录的版本保持不变并按各自版本的算法验证，可查可验不受影响）。

常用命令：

```bash
docker compose up --build -d   # 后台运行
docker compose ps              # 查看状态（含 healthcheck）
docker compose logs -f app     # 跟踪日志
docker compose down            # 停止（保留数据卷）
docker compose down -v         # 停止并删除抽签数据
```

健康检查：`GET http://localhost:3000/health` → `{"status":"ok"}`。

不使用容器时：`npm ci && npm start`（需 Node.js ≥ 22.13），同样监听 **http://localhost:3000**。

## 配置（环境变量，均有默认值）

| 变量 | 默认值 | 说明 |
|---|---|---|
| `PORT` | `3000` | 监听端口 |
| `HOST` | `0.0.0.0` | 监听地址 |
| `DATABASE_PATH` | 容器内 `/app/data/draws.db`，本地 `./data/draws.db` | SQLite 文件路径 |

SQLite 数据通过 compose 的命名卷 `draw-data` 持久化。

## 抽签流程

### 单 nonce 模式

1. **创建（承诺）**：提交有序分组 `groups`（不传 `participants`）。每组包含 `name`（组名，全局唯一）、`candidates`（组内候选，非空；同一候选不得出现在多个组）、`quota`（名额，不超过组人数的非负整数）；所有组的名额之和至少为 1。服务端生成 32 字节随机 seed，按分组顺序算出分组快照摘要，**只返回** `version`、`snapshotDigest` 与 `commitment = SHA-256("v3:<seed>:<snapshotDigest>")`，seed 在揭示前不会出现在任何响应中。
2. **揭示**：调用方提交一次 `nonce`（仅一次，重复提交返回 409）。服务端在**同一事务**（`BEGIN IMMEDIATE`）中锁定该抽签、落库 nonce、揭示 seed，并为每组用独立随机流算出中奖顺序后持久化。
3. **校验**：任何人用「承诺 + seed + nonce + 分组快照」即可独立重算承诺与各组中奖顺序；v3 承诺把组名、候选归属、名额与组序全部绑进摘要，任何一项改动都会使承诺校验失败。

### 多人承诺模式（熵汇聚）

创建抽签时在 `groups` 之外声明 `participants`（2–100 人，名单去重，顺序即后续 nonce 的拼接顺序），随后分两个阶段进行，所有写操作都在 `BEGIN IMMEDIATE` 事务内锁定抽签并**拒绝重复或越序操作**：

1. **承诺阶段（`pending → committed`）**：每位参与者调用
   `POST /draws/:id/participants/:name/commitment` 提交 `commitment = SHA-256(secret)`（64 位小写 hex）。第一个承诺落地后抽签进入 `committed` 阶段；同一参与者重复承诺返回 `409`；未声明的名字返回 `400`。承诺与揭示均允许乱序到达。
2. **揭示阶段（`committed → revealed`）**：
   - 只要还有参与者未承诺，任何揭示都会被拒绝（`409`，响应里给出 `waitingFor` 名单）。
   - 参与者调用 `POST /draws/:id/participants/:name/reveal` 提交 secret，服务端校验 `SHA-256(secret)` 与其承诺一致（不一致返回 `409`），重复揭示返回 `409`。
   - **最后一个揭示在同一事务内**：按创建时的固定参与者顺序拼接 `SHA-256(secret_i)` 得到 nonce（每段固定 64 hex，无分隔符、无歧义），为每组算出顺序并落库、揭示 seed。
3. **审计**：完成后的响应（及 `GET /draws/:id`）包含 `contributions` 列表——每位参与者的位置、承诺、secret、secret 哈希与两个时间戳。任何人都能用它重新拼出 nonce，再通过 `/verify` 独立复算。

## API

### 1. 创建抽签（v3 分组）

```bash
curl -X POST http://localhost:3000/draws \
  -H 'content-type: application/json' \
  -d '{"groups":[
        {"name":"A组","candidates":["alice","bob","carol"],"quota":1},
        {"name":"B组","candidates":["dave","erin"],"quota":1},
        {"name":"C组","candidates":["frank"],"quota":0}
      ]}'
```

```json
{ "drawId": "bde4b5b9-…", "mode": "single", "status": "pending", "version": "v3",
  "commitment": "9a34e8f9…", "snapshotDigest": "3e93e0a1…",
  "groups": [ { "name": "A组", "quota": 1, "candidateCount": 3 },
              { "name": "B组", "quota": 1, "candidateCount": 2 },
              { "name": "C组", "quota": 0, "candidateCount": 1 } ],
  "groupCount": 3, "totalQuota": 2, "candidateCount": 6, "createdAt": "…" }
```

创建校验（违反返回 `400`）：组名唯一；每组候选非空且同一候选不得跨组重复；`quota` 为不超过组人数的非负整数（允许 0，该组不产生中奖者）；全部组的名额之和至少为 1。旧版 `candidates`/`count` 创建格式已被 `groups` 取代（传入返回 `400`），但旧版记录仍可查询与校验。

### 2. 揭示（nonce 只能提交一次）

```bash
curl -X POST http://localhost:3000/draws/<drawId>/reveal \
  -H 'content-type: application/json' \
  -d '{"nonce":"public-input-2026-09-27"}'
```

```json
{ "drawId": "…", "mode": "single", "status": "revealed", "version": "v3",
  "commitment": "9a34e8f9…", "snapshotDigest": "3e93e0a1…",
  "seed": "bf723339…", "nonce": "public-input-2026-09-27",
  "groups": [ { "name": "A组", "quota": 1, "candidates": ["alice","bob","carol"],
                "order": ["bob","alice","carol"], "winners": ["bob"] },
              { "name": "B组", "quota": 1, "candidates": ["dave","erin"],
                "order": ["erin","dave"], "winners": ["erin"] },
              { "name": "C组", "quota": 0, "candidates": ["frank"],
                "order": ["frank"], "winners": [] } ],
  "createdAt": "…", "revealedAt": "…" }
```

每组独立开奖：`order` 为该组全量中奖顺序，`winners` 为前 `quota` 名（`quota` 为 0 时为空数组）。重复揭示返回 `409` 及首次揭示结果。

### 3. 查询状态

```bash
curl http://localhost:3000/draws/<drawId>
```

响应始终包含 `version`（新建抽签为 `v3`；更早的记录为 `v2`/`v1`）与 `snapshotDigest`（v1 记录为 `null`）。v3 记录包含 `groups`（组名、名额、候选；揭示后附各组 `order`/`winners`）、`groupCount`、`totalQuota`、`candidateCount`；v1/v2 记录包含 `candidates` 与 `count`。多人抽签的状态响应额外包含 `participants`（含每人 `status: pending|committed|revealed`、承诺与时间戳；secret 在整体揭示前不返回）以及 `committedCount` / `revealedCount` 计数。

### 3a. 多人模式：创建 + 承诺 + 揭示

```bash
# 1) 创建时声明参与者（顺序固定，即 nonce 拼接顺序）
DRAW=$(curl -s -X POST http://localhost:3000/draws \
  -H 'content-type: application/json' \
  -d '{"groups":[{"name":"A组","candidates":["alice","bob","carol"],"quota":1},
                  {"name":"B组","candidates":["dave","erin"],"quota":1}],
       "participants":["alice","bob","carol"]}')
ID=$(echo "$DRAW" | sed -E 's/.*"drawId":"([^"]+)".*/\1/')

# 2) 每人本地生成 secret，只提交其 SHA-256 承诺
for name in alice bob carol; do
  read -s secret"?$name secret: "   # 或自行生成：openssl rand -hex 32
  curl -s -X POST http://localhost:3000/draws/$ID/participants/$name/commitment \
    -H 'content-type: application/json' \
    -d "{\"commitment\":\"$(printf %s "$secret" | sha256sum | cut -d' ' -f1)\"}"
done

# 3) 全部承诺后再揭示 secret（可乱序；最后一个揭示触发开奖）
curl -s -X POST http://localhost:3000/draws/$ID/participants/carol/reveal \
  -H 'content-type: application/json' -d '{"secret":"carol-secret"}'
curl -s -X POST http://localhost:3000/draws/$ID/participants/alice/reveal \
  -H 'content-type: application/json' -d '{"secret":"alice-secret"}'
curl -s -X POST http://localhost:3000/draws/$ID/participants/bob/reveal \
  -H 'content-type: application/json' -d '{"secret":"bob-secret"}'
```

最后一个揭示的响应与单 nonce 模式结构一致（`seed` / `nonce` / 各组 `order` / `winners`），并额外给出：

```json
{ "mode": "multiparty", "status": "revealed", "version": "v3", "snapshotDigest": "3e93e0a1…",
  "nonce": "<sha256(alice-secret)><sha256(bob-secret)><sha256(carol-secret)>",
  "participants": [ { "name": "alice", "position": 0, "status": "revealed",
                      "commitment": "…", "secret": "alice-secret", "secretHash": "…" } ],
  "contributions": [ { "name": "alice", "position": 0, "commitment": "…",
                       "secret": "…", "secretHash": "…",
                       "committedAt": "…", "revealedAt": "…" } ] }
```

阶段/顺序错误码：

| 场景 | 状态码 |
|---|---|
| 未声明的参与者名字提交承诺/揭示 | `400` |
| 承诺不是 64 位小写 hex | `400` |
| 同一参与者重复承诺 / 重复揭示 | `409` |
| 尚有参与者未承诺就揭示（附 `waitingFor`） | `409` |
| secret 与其承诺不一致 | `409` |
| 开奖后再提交承诺/揭示（附最终 `draw`） | `409` |
| 对多人抽签调 `/reveal`，或对单人抽签调参与者接口 | `409` |

### 4. 独立校验（核心）

提交承诺、seed、nonce 与分组快照（带上 `version` 与 `snapshotDigest`），服务端重算分组承诺与各组结果，并逐项指出篡改：

```bash
curl -X POST http://localhost:3000/verify \
  -H 'content-type: application/json' \
  -d '{"version":"v3","snapshotDigest":"3e93e0a1…","commitment":"9a34e8f9…",
       "seed":"bf723339…","nonce":"public-input-2026-09-27",
       "groups":[
         {"name":"A组","candidates":["alice","bob","carol"],"quota":1,
          "order":["bob","alice","carol"],"winners":["bob"]},
         {"name":"B组","candidates":["dave","erin"],"quota":1,
          "order":["erin","dave"],"winners":["erin"]}
       ]}'
```

```json
{ "valid": true, "version": "v3", "snapshotDigest": "3e93e0a1…",
  "checks": { "groupNamesUnique": true, "candidatesUnique": true,
              "quotasInRange": true, "totalQuotaPositive": true,
              "snapshotDigestMatch": true, "commitmentMatch": true,
              "orderMatch": true, "winnersMatch": true },
  "expected": { "groups": [ { "name": "A组", "quota": 1, "order": ["…"], "winners": ["…"] } ] },
  "problems": [] }
```

任一字段被篡改时 `valid=false`，`problems` 会指明哪一项不一致：

- **组名/候选归属/名额篡改**：快照摘要重算结果变化 → `snapshotDigestMatch` 与 `commitmentMatch` 失败；
- **结构问题**：`groupNamesUnique`（组名重复）、`candidatesUnique`（候选跨组重复）、`quotasInRange`（名额超出 `[0, 组人数]`）、`totalQuotaPositive`（总名额不足 1）各自报警；
- **结果篡改**：每组可选附 `order`/`winners`，与重算结果不一致时 `orderMatch`/`winnersMatch` 失败，`problems` 指明是哪一组；不传则只校验承诺并重算期望值。

版本兼容：

- `version` 可选：提供 `groups` 时按 v3 校验（省略 `version` 时同样按 v3 处理）；提供 `candidates`/`count` 时按 v1/v2 校验（`version: "v2"` 重算候选快照摘要，省略 `version` 时按旧算法 `SHA-256(seed)` 校验——v2 之前的记录没有版本标记，始终走旧算法）。两种记录形状不能混传（`400`）。
- `snapshotDigest` 可选：传入时额外做 `snapshotDigestMatch` 检查（与重算摘要比对）；不传也能通过承诺校验发现快照篡改。

多人抽签可在 `/verify` 请求体中追加 `contributions`（按参与者顺序的 `{position, commitment, secret}` 列表），服务端会额外校验：

- `positionsComplete`：`position` 为从 0 开始的连续序号；
- `commitmentsOpen`：每条都满足 `SHA-256(secret) == commitment`；
- `nonceDerived`：按位置顺序拼接 `SHA-256(secret)` 恰好等于 `nonce`，并用重导出的 nonce 复算各组结果。

另外 `GET /draws/:id/verify` 可对服务端存储的记录做一致性重算：按记录持久化的 `version` 选择承诺算法（v3 同时把存储的 `snapshotDigest` 与分组快照重算结果比对，并检查已存结果的分组结构 `resultGroupsAligned` 与快照一致），多人模式自动带上 `contributions` 并检查贡献链。v1/v2 旧记录继续可查可验。

## 算法规范（第三方可独立复算）

- **seed**：32 字节加密随机数，hex 编码（64 字符）。
- **分组快照摘要（v3）**：按创建时的分组顺序拼接
  `snapshot = "v3\n" + <组数十进制> + "\n" + 每组 "<组名 UTF-8 字节数>:<组名><名额十进制>\n<候选数十进制>\n" + 每名候选 "<UTF-8 字节数>:<原字节>"`
  （数值均为十进制；候选间无分隔符，长度前缀保证无歧义；多字节字符按字节数计），
  `snapshotDigest = SHA-256(snapshot)`（对快照字符串的 UTF-8 字节求哈希）。
  例：`[{"name":"A","candidates":["alice","bob"],"quota":1},{"name":"B","candidates":["carol"],"quota":1}]`
  的快照为 `"v3\n2\n1:A1\n2\n5:alice3:bob1:B1\n1\n5:carol"`。
- **候选快照摘要（v2，旧记录）**：`snapshot = "<count 十进制>\n" + 每项 "<UTF-8 字节长度>:<原字节>"`，`snapshotDigest = SHA-256(snapshot)`。
- **承诺（按版本）**：
  - `v3`（新建抽签）：`commitment = SHA-256("v3:" + seed + ":" + snapshotDigest)`——承诺同时绑定 seed 与分组快照，组名、候选归属、名额或组序的任何改动都会使校验失败；
  - `v2`（旧记录）：`commitment = SHA-256("v2:" + seed + ":" + snapshotDigest)`；
  - `v1`（旧记录，无版本标记）：`commitment = SHA-256(seed)`（对 hex 字符串的 UTF-8 字节求哈希）。
- **参与者承诺**：`commitment_i = SHA-256(secret_i)`，同样为 64 字符 hex；揭示时必须精确匹配。
- **熵汇聚 nonce**：多人模式下，按创建时声明的固定参与者顺序（position 0…n−1）拼接
  `nonce = SHA-256(secret_0) ‖ SHA-256(secret_1) ‖ … ‖ SHA-256(secret_(n−1))`，
  每段固定 64 hex（无分隔符）。单 nonce 模式直接使用调用方提交的 nonce。
- **随机流**：
  - v3 分组抽签：第 `g` 组（0 起始）的第 `i` 块为 `SHA-256("{seed}:{nonce}:{g}:{i}")`；
  - v1/v2 旧记录：第 `i` 块为 `SHA-256("{seed}:{nonce}:{i}")`；
  每块 32 字节按大端序切成 8 个 uint32，依次消费。
- **拒绝采样**：取 `[0, n)` 均匀整数时，令 `limit = floor(2^32 / n) * n`，丢弃 `x >= limit` 的样本，返回 `x % n`，消除模偏差。
- **Fisher-Yates**：每组对各自的候选副本从末尾向前，`j = uniform(i + 1)` 交换，得到该组全量中奖顺序；前 `quota` 个为该组中奖者。

## 本地开发（可选）

需要 Node.js ≥ 22.13（内置 `node:sqlite`）：

```bash
npm ci
npm start     # http://localhost:3000
npm test      # node:test 测试套件（含无偏性统计检验）
```

## 项目结构

```
src/lottery.js          承诺生成（v1/v2/v3）、候选/分组快照摘要、SHA-256 随机流（含分组流）、拒绝采样、Fisher-Yates、多人 secret 哈希汇聚
src/db.js               SQLite 连接、自动建表与旧版 schema 迁移（v0 → v1 → v2 → v3，v3 增加 groups 列）
src/app.js              Fastify 路由（分组创建 / 单人揭示 / 多人承诺·揭示 / 查询 / 按版本校验）
src/index.js            入口：配置、启动、优雅退出
test/api.test.js        单 nonce 分组模式端到端与篡改检测测试
test/groups.test.js     v3 分组快照、分组随机流、名额边界、分组篡改检测与多人分组抽签测试
test/multiparty.test.js 多人承诺模式阶段锁定、越序拒绝、汇聚与审计测试
test/snapshot.test.js   v1/v2 旧记录校验、按版本承诺与旧库迁移测试
```
