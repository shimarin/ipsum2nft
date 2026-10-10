# ipsum2nft

[IPsum](https://github.com/stamparm/ipsum)（複数ブラックリストの集計IPリスト、日次更新）を
nftables用のテーブル定義ファイルに変換するツール。毎実行でフィード全文を
HTTPSでダウンロード（git依存なし、約1.9MB）し、`nft -f` でロードできるファイル
（テーブル＋セット＋ドロップチェーン）を生成する。

## 使い方

```sh
./ipsum2nft.py                      # 全IP（スコア1以上）で ipsum.nft を生成
./ipsum2nft.py --min-score 3        # アップストリーム推奨の閾値（3以上のブラックリスト掲載）
./ipsum2nft.py --install            # 生成後、実行中カーネルへ（再）ロード（root要）
```

`--install` なしの場合は最後にrootでのロード手順が表示される。再実行時は
[更新](#更新再実行)の手順に従い、構造が同じならセット内容をアトミックにだけ差し替える
（既存テーブルがあっても問題ない）。

```sh
./ipsum2nft.py uninstall              # テーブルを削除（root要、idempotent）
./ipsum2nft.py uninstall --table foo  # カスタムテーブル名を削除
```

### オプション

| オプション | 説明 |
|---|---|
| `--min-score N` | 掲載ブラックリスト数が N 以上のIPのみ採用（既定: 1 = 全件）。`levels/N.txt` と同等の絞り込み |
| `--add IP` | 追加でセットに含めるIP/CIDR（繰り返し指定・カンマ区切り可）。`--min-score`の対象外。`--merge`併用時は隣接エントリと統合される。実測で特定のIPのブロックを確認したい場合に便利 |
| `--log` | アウトバウンドヒット（output daddr / forward daddr）をレート制限付きでカーネルログ(journald)に記録 |
| `--log-group N` | 同アウトバウンドヒットをNFLOGグループNに送出（同梱の `daemon` サブコマンド、または lateral-hoihoi 等のユーザースペースリーダーでMAC付き記録＋メール警報。負荷時の完全記録は保証しない） |
| `--log-rate RATE` | `--log` のレート制限（既定 `10/minute`）。`N/second\|minute\|hour\|day\|week` の正の整数 N を要求し正規化する（nft は `sec` の短縮形や単位なしを拒否し、先頭ゼロは8進数と解釈するため `010/minute` は `10/minute` に正規化される） |
| `--merge` | 隣接・重複するprefixを統合（256個の/32 → /24 等）。本リストは118,773 → 約90,000件に圧縮 |
| `--chains {both,all,input,output,forward,none}` | 生成するドロップチェーン（既定: both = input+output）。ルーターでは `all`（+forward）。`none` でセットのみ |
| `--table` / `--set` | テーブル名（既定: `ipsum`）/ セット名（既定: `blocklist`）。**名前を変更すると旧テーブルは削除されない**ので、旧名で `uninstall --table <旧名>` を実行すること |
| `--output FILE` | 出力先（既定: `ipsum.nft`） |
| `--chunk N` | 要素を追加N件ごとにファイル分割（既定: 0 = 単一ファイル） |
| `--list FILE` | フィード以外の一覧ファイル（`levels/*.txt` 等、IPのみの形式可）を直接変換 |
| `--no-fetch` | ダウンロードせず、最後にダウンロードしたローカルコピーを使う |
| `--list-dir DIR` | ダウンロードしたフィードを置くディレクトリ（既定: `./ipsum`） |
| `--url URL` | ダウンロードするフィードのURL（既定: stamparm/ipsum の raw.githubusercontent.com 版） |

### 生成ファイルの例

```nft
table inet ipsum {
    set blocklist {
        type ipv4_addr
        flags interval
        elements = { 1.0.126.255/32, 1.0.164.165/32, ... }
    }
    chain input {
        type filter hook input priority -200; policy accept;
        ip saddr @blocklist counter drop
    }
    chain output {
        type filter hook output priority -200; policy accept;
        ip daddr @blocklist counter drop
    }
}
```

既存のテーブルに組み込む場合は、set定義部分だけ抜き出して同一テーブル内に配置し、
ルールから `@blocklist` を参照すること。

### ルーター（中継トラフィック）の場合

INPUT/OUTPUTチェーンはルーター自身の送受信だけを守り、LAN↔WANの中継トラフィックは
FORWARDでしか見えないため、ファイアウォールルーターでは **`--chains all`** を使うこと。

```sh
./ipsum2nft.py --min-score 3 --chains all --install
```

forwardチェーンには saddr/daddr 両方のdropルールが入る（外部からの悪意あるアクセスと
内部クライアントのC2通信の両方を遮断）。検証済み: vethで2クライアント+ルーターを構成し、
リスト入りIP経由の中継pingはforwardのsaddrルールでdrop、リスト外のpingは通過することを確認。

なお、中継元IPにルーター側がルートを保持していないと（テスト環境でWAN相当の
デフォルトルートが無い等）、カーネルがmartian sourceとしてFORWARD以前にdropするため、
本ルールに到達しない点に注意（実ルーターではデフォルトルートがあるため通常は問題ない）。

### アウトバウンドヒットの記録・警報（`--log` / `--log-group`）

input/forward の saddr 方向（外部の悪意あるIPからのアクセス）は脅威リストの想定内ノイズなので
記録しない代わりに、**送信側がブロック済みIPに接触した方向** — output daddr（ルーター本体の
C2等）と forward daddr（**内部ホストのC2等、最も注意を要するケース**）— は記録対象とする。
この2つのルールにだけ log が入る:

```nft
# --log の場合（レート制限付き2ルール。超過分は無言でdrop）
# OUTPUT の log には flags skuid 付き（ソケット所有者の UID/GID を記録、
# 侵害後の Web サーバ実行ユーザー等の特定に有用。FORWARD はローカル
# ソケットが無く付かない）
ip daddr @blocklist limit rate 10/minute counter log prefix "ipsum-out: " flags skuid drop
ip daddr @blocklist counter drop
ip daddr @blocklist limit rate 10/minute counter log prefix "ipsum-fwd: " drop
ip daddr @blocklist counter drop

# --log-group 6 の場合（NFLOG 1ルール、無条件drop）
ip daddr @blocklist counter log group 6 prefix "ipsum-fwd: " snaplen 128 drop
```

- `--log`（軽量）: カーネルリングバッファ/journald へ。
  `journalctl -t kernel | grep ipsum-fwd` で確認できる。
  行には IN=/OUT= と src/dst IP 等が乗る。記録のトリガー化は journald の
  監視（logwatch 等）で組む。
  前提: カーネルの syslog ロガーが有効であること（`nf_log_syslog` モジュール、
  Gentoo では netfilter 有効なら同梱）。確認: `cat /proc/sys/net/netfilter/nf_log/2`
  が `nf_log_ipv4` を指していれば OK。行が出ない場合の第一候補はこれ。
- `--log-group N`（NFLOG → ユーザースペースリーダー）: NFLOG 経由でパケットごと
  渡す。記録内容: 時刻 / src・dst IP / **src・dst MAC** / プロトコル / ポート(やICMP type) /
  受信IF / prefix（`ipsum-out: ` か `ipsum-fwd: ` で方向が識別できる）。
  同梱の通知デーモン（[`ipsum2nft daemon`](#通知デーモンipsum2nft-daemon)）がそのまま使えるほか、
  [lateral-hoihoi](https://github.com/shimarin/lateral-hoihoi) デーモンもそのまま使える（group 番号を conf
  に合わせるだけ。検出名義はラテラルムーヴメントだが NFLOG 到着イベント自体は汎用的）。
  sandbox実測例（内部ホスト 10.99.1.2 がブロック済みIPへ ping したケース）:

  ```
  ■ 送信元 10.99.1.2  (MAC 9a:f6:91:e3:c5:42  IF#3)
     2026-10-10 08:01:26 ICMP  2.57.122.53 type=8/code=0  1  ipsum-fwd:
  ```

  注意: NFLOG グループは同時期に1つのリーダーしか bind できない。同じルーターで
  lateral-hoihoi 本来の罠検出も動かす場合は group 番号を分け、リーダーも2つ立てること
  （またはグループを統一して1つのリーダーに集約する）。

### 通知デーモン（`ipsum2nft daemon`）

`--log-group` で NFLOG に送ったヒットを読み取り、メールで通知する自前の通知デーモン。
lateral-hoihoi と同じ NFLOG 読み取り機構を同梱しているため、ipsum2nft 単体で完結する。

```sh
ipsum2nft daemon                    # /etc/ipsum2nft.conf で起動
ipsum2nft daemon --dump             # 動作確認: メールを送らず標準出力に表示
ipsum2nft daemon --test-mail        # 設定でテストメールを1通送って終了
```

設定ファイルは `/etc/ipsum2nft.conf`（例は `ipsum2nft.conf.example`。SMTP パスワードを
含むので root:root 0600 を推奨）。**`[nflog] group` は `--install` 時の `--log-group N`
と一致させること**（同梱の `ipsum2nft.service` は 6 を使う）:

```ini
[nflog]
group = 6

[detection]
# この秒数ぶんを1通に集約(メール洪水対策)
aggregation_window = 60
# 同一送信元の再通知抑制(長時間スキャン対策)
cooldown = 3600

[smtp]
host = smtp.example.com
port = 587
tls = starttls
user = alerts@example.com
password = ...
# 自前CAを使う場合は証明書ファイル/ディレクトリを指定(TLS検証は既定で有効)
# cafile = /etc/pki/my-ca.pem
# capath = /etc/pki/ca
timeout = 30

[mail]
subject_prefix = [ipsum2nft]
hostname = auto
from = ipsum2nft@example.com
to = soc@example.com
```

systemd での運用（`--log-group` を使う場合のみ）:

```sh
systemctl enable --now ipsum2nft-notify.service
journalctl -u ipsum2nft-notify
```

- root 実行（NFLOG グループの bind に CAP_NET_ADMIN が必要）。
  unit には `CapabilityBoundingSet=CAP_NET_ADMIN` 等の追加ハードニング付き。
- bind なしで `--log-group` を付けていても drop 自体には影響しない（カーネルが
  ログをスキップするだけ）。ただし前提が2つある: 同じネットワーク名前空間で
  他に group 6 を使っていないこと（別用途のリーダーが起きているとそのリーダーに
  イベントが流れる）、カーネルの NFLOG 対応（nfnetlink_log）が利用可能であること。
- デーモン停止中はヒットは通知されない（NFLOG にバッファリングは無いため）。
- 起動時は config の ACK を**期限付きで待ってから**受信開始する（この間に届いた
  パケットは保持して最初のリードで返す）。権限不足やグループが別プロセスに bind
  されている場合は起動を中止し非零終了（`Restart=on-failure` が効く）。
- ヒットは (送信元, 集約キー) 単位で**増分集約**されるため、メモリとメールサイズは
  パケット数に比例しない（ウィンドウあたり 4096 ペアまで集約し、超過分は件数だけ
  メールに計上）。集約ペア数の上限は現ウィンドウと**再送待ち分（SMTP 失敗で保持中）
  を合わせた合計1つ**であり、SMTP 障害が長く続いても保持量は増えない（既存キーの
  件数更新は継続し、入らない新規キー分を省略件数に計上する）。SMTP 送信失敗時は
  cooldown を適用せず保持し、次のウィンドウで再試行する（省略件数も一緒に保持し、
  成功した通知で計上される）。
- **負荷時の完全記録は保証しない**: NFLOG ルールにはレート制限が無い（制限超過の
  トラフィックを通過させないため）ため、高レートなヒットではカーネル側の
  netlink コピー/転送負荷やバッファオーバーフロー（ENOBUFS）による取りこぼしが
  起こり得る。ユーザースペースの集約上限はメモリを守るだけで、このカーネル側
  経路を保護するものではない。`limit ... log ... drop`＋無条件 `drop` の
  2ルール方式（`--log` と同型）でカーネル側も制限できるオプションは次の増分で
  検討予定。導入時は、グローバルな limit では1つの送信元が枠を使い切って他送信元
  の通知を失い得る点に注意が必要。
- TLS は既定で証明書・ホスト名検証（`ssl.create_default_context()`）。
  私設 CA 用には `[smtp] cafile` / `capath` を指定できる。cafile は
  `ssl` が即座に読み込むが、capath はハンドシェイク時の遅延読込のため存在が
  例外にならない。このため起動時に cafile の存在（ファイル）・capath の存在
  （ディレクトリ）を明示チェックし、壊れた指定を最初の警報を待たずに検出する。
  capath のハッシュ済み CA 配置そのものの最終確認は実 TLS 接続時に行われる。

### 既存ルールのsetとの関係

`--install` は `inet ipsum` テーブルの中身だけを扱い、他テーブル・既存ルールには一切
触れない。置換は単一 netlink batch として原子に行われるため、**ロード失敗時でも
直前のテーブルはそのまま維持される**（sandbox実測: 不正な新定義では旧テーブルの
set・chain・ルール・drop機能がすべて保持）。

評価セマンティクスは「独立して先にマッチした方が勝つ」ではなく、nftables の
フック共通の性質に従う: 同一フックの全ベースチェーンはpriority順に走査され、
**`accept` は走査を止めない**（nft(8): accept は "Evaluation continues in the next
base chain ... the packet can still be dropped"）。止められるのは `drop` だけ。
したがって（いずれもsandboxで実測済み）:

- 既存の accept ルール（priority が -200 より前でも後でも）は**このブロックを回避できない**
- 逆に、この drop を後続の accept で無効化することはできない
- priority が -200 より小さい（より早期の）既存 drop だけが、パケットを我々のチェーン
  に到達させない（＝すでに遮断済みで無害。ただし我々のカウンターには計上されない）
- 付随効果: 既存の `ct state established accept` 等でも確立セッションを守れないため、
  ブロック対象IPとの**進行中のセッションも切断される**（脅威リストとしては通常望ましい挙動）。
  例外: flowtable / ハードウェアオフロードで FORWARD フックをバイパスしている既存フローは
  この経路を通らないため、別途扱う必要がある

特定IPを除外（ホワイトリスト）したい場合、別テーブルの accept では不十分（我々が drop
するため）。我々のチェーン内 drop より前に例外を挿入する:

```sh
nft insert rule inet ipsum input  ip saddr 192.0.2.10 accept   # INPUT の例
nft insert rule inet ipsum output ip daddr 192.0.2.10 accept
```

注意: **フル置換**（構造変化・構造チェック失敗時の `--install`）でテーブルが再作成される
ため、この例外はそのタイミングで消える。ただし通常の in-place 更新（構造不変時の再実行）
ではチェーンは触られないため例外は残る（構造チェックは「生成した必須ルールが存在するか」
のチェックであり、追加した accept ルールは許容する）。

### 更新（再実行）

最新のリストを取り込むには**同じコマンドラインを再実行するだけ**（`--install` 付き）。
ダウンロード → 変換 → 適用まで一手で行われる。どの経路も単一 netlink batch であり、
セットが空になる瞬間も壊れた中間状態も**存在しない**（空白期間ゼロ。ロード失敗時は
旧テーブルが保持される。いずれも sandbox でプローブ ping / 不正定義注入により実測）。

- **構造不変（通常時）**: セット内容のみを `flush set` + `add element` の単一
  `nft -f` 呼び出しで更新（プローブ ping で 225/340 個すべて 0 通過、フルリスト
  118,773 件版も約 2 秒で 0 通過）。
- **フル置換時**（`--chains` / `--log` / `--log-group` / `--log-rate` / `--table` /
  `--set` の変更、初回インストール、state ファイル欠如、**実テーブルの構造チェック失敗**）:
  `delete table` + 新定義（chunk 含む）を単一ファイル・単一 `nft -f` で原子置換。
  不正な新定義では batch が丸ごと破棄され旧テーブルが保持される（実測）。
- **in-place 適用前の構造チェック**: sidecar の fingerprint 一致に加え、カーネル側の
  実テーブル（`nft list table` のパース）で必須 set の型、必須 chain の
  hook/priority/policy、**必須 drop ルールの全条件**を確認する（nft 1.1.7 の
   この Gentoo build は JSON 非対応のためテキストパース）。ルールの本文
   （set照合とdropの間）を counter / limit / log の文に分解し、**生成した文の
   集合と完全一致**を求める（部分一致ではない）。したがって `meta skuid N`
   等の追加マッチ条件、quota、comment、余分な limit はすべて不一致となり、
   `group 5` が `group 50` に書き換えられているような境界の違いも検出できる
   （sandbox で両シナリオを検出→フル置換復元を実測）。具体的には、記録方向には
   「set照合だけで無条件に drop する plain ルール」の存在を必須とし
   （rate-limited log ルールだけでは制限超過のトラフィックが通過し得る）、log
   ルールは prefix / `limit rate` / `flags skuid`（OUTPUTのみ）/ NFLOG の
   `group`・`snaplen` の値まで一致させる（NFLOG ルールに limit が無いことも
   確認する）。追加ルール（手動whitelist）は許容。
  外部操作でテーブルが弱められていた場合（set だけ残して chain が消えている、
  plain ルールが rate-limited ルールに差し替えられている等）は in-place に
  進まず、フル置換で回復する（いずれも sandbox 実測）。fingerprint には生成
  ルールのスキーマバージョン（`SCHEMA_VERSION`）も含まれるため、コード側の
  ルール変更を古いテーブルに適用し忘れない。
- 構造の同一判定の補助情報は `<output>.state`（fingerprint sidecar）。`uninstall`
  時に一緒に削除される。
- `--install` では chunk 指定の有無にかかわらず単一 batch でロードする（原子性の
  ため）。`--chunk` は `--install` なしの手動ロード時の分割用に残っている。

### 運用（systemd）

```sh
make install                  # /usr/local/bin/ipsum2nft と /etc/systemd/system/ipsum2nft.{service,timer,boot.timer,notify.service}
systemctl daemon-reload
systemctl enable --now ipsum2nft.timer ipsum2nft-boot.timer
```

- **`ipsum2nft.timer`**（日次）: 毎日 **04:00 UTC**（フィードの日次更新 03:00 UTC+2/3
  = 01:00/00:00 UTC の後に余裕を持たせた時刻）＋乱数遅延15分。
  `Persistent=true` で電源オフ中に逃した実行は起動時に1回追走する。
- **`ipsum2nft-boot.timer`**（起動時）: カーネルのテーブルは再起動で消えるため
  起動後10分に再適用。`RandomizedDelaySec` は付けていない（乱数遅延は全トリガーに
  適用されるため、日次timerとは分離した）。ネットワーク未起動時はダウンロードが
  失敗するが、ツールが前回のローカルコピーで適用するため防御は確保される。
- **`ipsum2nft.service`**（oneshot、root）: 上記両timerから起動され
  `--min-score 3 --install --log-group 6 --list-dir /var/lib/ipsum2nft
  --output /var/lib/ipsum2nft/ipsum.nft` を実行する。
  オプションを変えたい場合（ルーターで `--chains all`、`--log-group` の
  group 番号変更等）は unit の `ExecStart=` を編集して `systemctl daemon-reload`。
  `--log-group 6` は既定で付いている（[通知デーモン](#通知デーモンipsum2nft-daemon)が
  そのまま使えるようにするため）。デーモンを使わない場合も無害（bind なしなら
  カーネルはログをスキップし、drop はそのまま機能する）。
- **`ipsum2nft-notify.service`**（optional）: `--log-group` ヒットの通知デーモン。
  使う場合は `/etc/ipsum2nft.conf` を用意（`ipsum2nft.conf.example` を複製・編集、
  `chmod 0600`）して `systemctl enable --now ipsum2nft-notify`。
  `[nflog] group` は `ipsum2nft.service` の `--log-group` と一致させること。
- 状態（ダウンロード済みフィード、生成ファイル、`.state`）はすべて
  `/var/lib/ipsum2nft` 以下。ディレクトリは `StateDirectory=` により自動作成される。
- 実行ログは journal: `journalctl -u ipsum2nft`（更新状況の点検にも使う）。
  ダウンロード失敗時は `using existing copy ... (N days ago)` と経過日数が出る。
- ダウンロードしたフィードは **書き込み前に厳格検証**される: ヘッダ、
  各データ行が「アドレス（IPv4/IPv6 の単一IPまたはCIDRプレフィクス）＋正の
  整数score」のちょうど2列、かつ1000件以上。エラーページや壊れた応答は
  前回の正常コピーを上書きできない（score の欠落は `--min-score` を無効化し
  うるため不可）。将来 v6 の `/64` 単位プレフィクスが提供されてもそのまま
  適用される（遮断範囲はフィードが示す範囲のまま）。
- 停止/削除（この順番）:
  1. `systemctl disable --now ipsum2nft.timer ipsum2nft-boot.timer`
     （通知デーモンを使っている場合、`ipsum2nft-notify` も）
  2. `ipsum2nft uninstall --output /var/lib/ipsum2nft/ipsum.nft`（カーネルから外す）
  3. `make uninstall`（インストール済みファイルのみ削除。2を飛ばすとテーブルが残る。
     `/etc/ipsum2nft.conf` は削除対象外なので必要なら手動で）

cron での代替例（systemdを使わない環境）:

```cron
# フィード更新（UTC+2 の 03:00 頃）より遅い時刻に実行。
# CRON_TZ は cronie 等が対応（対応しない cron ならホストTZに換算して
# 時刻を書く、例: JST では 0 13 * * *）。システムcrontab (/etc/crontab)
# に書く場合はユーザー欄（root）も必要。
CRON_TZ=UTC
0 4 * * * /usr/local/bin/ipsum2nft --min-score 3 --install --list-dir /var/lib/ipsum2nft --output /var/lib/ipsum2nft/ipsum.nft
```

## 量の問題（118,773件）について

nftablesにそのまま渡せるか検証した結果（kernel 7.2.9 / nftables 1.1.7, Gentoo）:

- **フルリスト（118,773件）の単一ファイル（約1.9MB）を `nft -f` 1発でロード可能**（約0.2秒、
  ツール全体の1実行はダウンロード込みで約1〜2秒）
- 要素数・netlinkメッセージサイズともに問題なし（`flags interval` のrbtreeベースset）
- veth経由のpingで実トラフィック検証済み: リスト入りIPはdrop、リスト外は通過（誤dropなし、
  v4+v6・input+forward で確認）
- カーネルメモリは cgroup 計測（kmem 込み）でフルリスト約22MB（1件あたり約180B程度）で
  実務上問題なし
- 万一、netlinkバッファが小さい環境でロード失敗する場合は `--chunk 30000` 等で分割可能
  （5ファイル分割でも計0.6秒でロード確認済み）。`--install` は常に単一batchで
  ロードするため、分割は手動ロード時のみ有効

## 実装メモ

- prefix（CIDR）要素を含むsetには nftables で `flags interval` 必須
  （`type ipv4_addr prefix` という書式はこの版のnftには存在しない）
- chainの `priority` にシンボル名（`filter` 等）を無修飾で書けないため数値 `-200` を使用
- interval setは隣接レンジをカーネル側で自動マージする
- 更新の全経路（in-place・フル置換）が単一 batch のアトミック適用（空白ゼロ、
  失敗時は旧テーブル保持、ともに実測済み）
- interval set は重複（包含）するエントリを拒否するため、`--add` のCIDR等による
  包含関係は常に正規化して除去する（集合は不変）。隣接prefixの圧縮は `--merge` のみ
- IPv6: v4/v6 混合リストに対応済み（`blocklist`/`blocklist6` の set 分離＋ip6 ルール）。
  sandbox 実測で v6 の drop/通過ともに確認済み。現行フィードは IPv4 のみで、
  将来フィードが v6 を含める（単一ファイル混合 or 別ファイル）場合は
  変換側はそのまま使える（別ファイルの場合は fetch 側=複数 URL 化のみ）
