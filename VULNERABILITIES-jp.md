# Vulnerability Cases in JSEF (Japanese)

このドキュメントは、Java Security Education Framework (JSEF) に実装されているすべての脆弱性事例の包括的なリストを提供し、検索と学習が容易になるように分類されています。各項目は固有のセキュリティ欠陥を表しており、多くの場合、非安全なコード実装と安全なコード実装の両方が含まれています。

> 現在リポジトリには **133 件**の機械可読 `// [CHECKPOINT]` 注釈があり（`src/main` の既存脆弱性 + `benchmark/cases` 勾配サンプルを網羅）、**93 件の VULN** + **40 件の SAFE**、**34 種の CWE** をカバーしています。以下は実装済みの代表的な事例を脆弱性ファミリ別に並べたものです（網羅的な枚举ではなく、全リストは `benchmark/expectedresults.csv` を参照）。

---

## 📋 脆弱性事例分類（50以上の脆弱性ファミリをカバー）

### 1. インジェクション系脆弱性
- SQLインジェクション：基本連結、複数フィールド連結、プリペアドステートメント比較（安全混同サンプル付き）
- コマンドインジェクション：Runtime.exec() 乱用、ProcessBuilder インジェクション、ファイル間呼び出しチェーン汚染
- 式 / スクリプトエンジンインジェクション（式インジェクション大家族）：
  - SpEL インジェクション（Spring4Shell `class.module.classLoader` フレームワーク意味専用事例を含む）
  - Groovy インジェクション（GroovyShell / GroovyScriptEvaluator）
  - MVEL インジェクション（MVEL.eval / executeExpression）
  - BeanShell インジェクション（BshScriptEvaluator / Runtime.exec）
  - OGNL インジェクション（Ognl.getValue / Runtime.exec）
  - ScriptEngine インジェクション（ScriptEngine.eval / CompiledScript.eval）
  - JNDI インジェクション（InitialContext.lookup / RMI）
  - Log4j JNDI インジェクション（CVE-2021-44228 抽象）
- テンプレートインジェクション：FreeMarker / Thymeleaf ビュー名/内容連結（CWE-1336）
- XSS：反射型 XSS（安全混同サンプル付き）
- LDAPインジェクション：ディレクトリサービスクエリのインジェクションシナリオと防御策
- XPathインジェクション：XPath.compile / DOMXPath.selectNodes
- XML外部エンティティ（XXE）：DocumentBuilder で DTD 未無効化による情報漏洩（安全設定対照付き）
- NoSQLインジェクション：Spring Data Mongo 間接汚染（CWE-943）
- サーバーサイドリクエストフォージェリ（SSRF）：内部サービスアクセスとデータ窃取（イントラ IP ホワイトリスト混同 SAFE 付き）

### 2. 認証・認可系脆弱性
- 認証バイパス：Cookie/ロール偽造、セッションチェック欠落（CWE-287）
- 認可バイパス / 不正アクセス（特権昇格）：水平・垂直方向の権限昇格（CWE-285）
- IDOR（安全でない直接オブジェクト参照）：オブジェクト帰属意味欠落 + 帰属チェック済みの混同 SAFE（CWE-639）
- 弱いパスワードのリスク：平文パスワード検証、複雑性回避（CWE-521）
- デフォルト認証情報：デフォルト管理者ユーザー/パスワード未変更（CWE-798）
- JWT脆弱性：alg=none / 弱鍵 / ハードコード + ゆるい検証混同（CWE-345）

### 3. 機密情報漏洩
- レスポンスへの機密情報：平文パスワード/身分証/クレジットカードをレスポンス本体へ（CWE-532）
- 弱ハッシュ保存：MD5/SHA1 平文パスワードハッシュ（CWE-327、PBKDF2 修正対照付き）
- ハードコード認証情報/鍵：DB接続ハードコード、ハードコード AES 鍵（CWE-798 / CWE-798 ECB）
- エラーページ漏洩 / ログ漏洩：スタックトレースと設定情報の露出（教育例）

### 4. 不適切な設定
- 不適切な数値・日付入力検証：巨大数 DoS、フォーマット曖昧性（CWE-20）
- デフォルトパスワードリスク（第2節参照）
- 不安全 HTTP メソッド / オープンリダイレクト：リダイレクト URL ホワイトリスト欠落、`redirect:` プレフィックス迂回（CWE-601、ホワイトリスト SAFE 付き）
- CORSの不適切な設定：Access-Control-Allow-Origin:* 過度に緩いクロスオリジン（CWE-942）
- クリックジャック / セキュリティヘッダ欠落：X-Frame-Options / CSP 欠落（CWE-1021、ヘッダ設定 SAFE 付き）
- レート制限欠落：SMS OTP の頻度制限なし（CWE-307、制限付き SAFE）

### 5. 逆シリアライズとその他の高危険脆弱性
- Java ネイティブ逆シリアライズ：ObjectInputStream.readObject、Jackson enableDefaultTyping、CC gadget chain（CWE-502、L5 gadget chain 事例含む）
- Fastjson 逆シリアライズ：JSON.parseObject / AutoType（CWE-502）
- Jackson 多態逆シリアライズ：@JsonTypeInfo ホワイトリスト欠落（CWE-502、allowlist SAFE 付き）
- YAML 逆シリアライズ：SnakeYAML load/loadAs（CWE-502）
- 依存関連 CVE 事例：
  - Spring AMQP 逆シリアライズ（CVE-2023-34050、allowlist SAFE 付き）
  - Redisson 逆シリアライズ（CVE-2023-42809、allowlist SAFE 付き）
- 競合状態（Race Condition）：非原子的 read-modify-write（CWE-362、synchronized SAFE 付き）
- ハッシュ衝突攻撃：HashMap ユーザー制御 key 性能劣化 DoS（CWE-694、SHA-256 key SAFE 付き）
- ReDoS：破滅的バックトラック正規表現 `(a+)+b`（CWE-1333）
- パストラバーサル：ディレクトリトラバーサルでのシステムファイル読み取り（CWE-22、Files.newInputStream SAFE 付き）
- マスアサインメント：@RequestBody が isAdmin をバインド（CWE-915、DTO SAFE 付き）
- JSONP コールバックインジェクション：callback 文字列連結（CWE-352）
- ヘッダインジェクション：HttpHeaders.add インジェクション（CWE-113）
- 危険操作：sun.misc.Unsafe 任意メモリ読み取り（CWE-111）
- ビジネスロジック欠陥：符号チェックなしの残高改ざん、価格改ざん、クーポン悪用、在庫オーバーセル（CWE-840、クーポン SAFE 付き）

**注:** CVE-2023-34034 (Spring WebFlux 認可バイパス) および CVE-2023-44487 (HTTP/2 Rapid Reset 攻撃) のような一部のCVEは、Spring WebFluxフレームワークに依存しているか、低レベルのネットワークプロトコル問題であるため、本プロジェクトのSpring MVCのアプリケーションシナリオには直接適用できないか、簡単なコントローラでデモンストレーションすることが困難です。そのため、これらは記録のみとし、具体的なチュートリアル事例としては実装されていません。
