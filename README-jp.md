# Java Security Education Framework (JSEF) - Spring Boot セキュリティ実践プラットフォーム
[![GitHub Stars](https://img.shields.io/github/stars/XiaomingX/JSEF?style=social&label=Star%20This%20Repo)](https://github.com/XiaomingX/JSEF)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![PRs Welcome](https://img.shields.io/badge/PRs-Welcome-brightgreen.svg)](CONTRIBUTING.md)
[![Java Version](https://img.shields.io/badge/Java-17%2B-blue.svg)](https://www.oracle.com/java/technologies/downloads/#java17)
[![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.x-orange.svg)](https://spring.io/projects/spring-boot)
[![Docker Ready](https://img.shields.io/badge/Docker-Supported-blue.svg)](docs/docker-deployment.md)

> **再現可能、実践可能、学習可能**なSpring Boot Webセキュリティ実験フレームワークで、開発者がWebセキュリティ脆弱性の原理と防御策を迅速に習得するのを支援します。


## 📖 プロジェクト概要
**Java Security Education Framework (JSEF)** はSpring Boot 3.xをベースに構築されたWebセキュリティ実践プラットフォームで、**開発者、セキュリティリサーチャー、大学生、企業研修**向けに設計されています。**35種類以上の実際のビジネスシナリオに基づくセキュリティ脆弱性事例**（インジェクション攻撃、不正アクセス、機密情報漏洩などのコアタイプを含む）を通じて、「**原理説明→脆弱性再現→コード比較→修復検証**」の完全な学習サイクルを提供し、学習者が「理論」から「実践」へとWebセキュリティのコア能力を迅速に習得するのを助けます。

本プロジェクトは複雑な環境に依存せず、ローカルでのワンクリック起動とDockerデプロイをサポートしています。すべての脆弱性事例は実際のビジネスロジックに基づいて設計されており、「脆弱性のための脆弱性」というデモ用コードを回避し、実際の開発シナリオにより近い形で提供しています。

**新しい構造の説明:** プロジェクトコードはリファクタリングされました。すべての脆弱性関連コントローラは現在 `com.freedom.securitysamples.vulnerability` パッケージの下にあります。各脆弱性カテゴリは、直接比較学習を容易にするために、さらに `vuln` (安全でない/脆弱な実装を含む) および `sec` (安全な/修正された実装を含む) サブパッケージに分割されています。APIルートも `/api/v1/{vulnerability-type}/unsafe/{scenario}` および `/api/v1/{vulnerability-type}/safe/{scenario}` の形式に統一されています。


## 🔥 コアメリット（なぜJSEFを選ぶのか？）
| メリット | 詳細説明 |
|-----------|----------------------|
| **脆弱性事例の実際の再現性** | 35種類以上の脆弱性がOWASP Top 10の全てのタイプをカバーし、各事例はユーザーログイン、データクエリ、ファイルアップロードなどの実際のビジネスシナリオを模擬しています。 |
| **完全な学習サイクル** | 各脆弱性には「原理ドキュメント＋再現手順＋非安全コード＋安全コード比較＋防御ベストプラクティス」が付属しています。 |
| **デプロイのハードルゼロ** | `mvn`によるワンクリック起動、Dockerコンテナ化デプロイをサポートし、データベース/ミドルウェアの手動設定は不要です。 |
| **明確なコード規約** | Spring Bootのベストプラクティスに基づいてコーディングし、非安全なコードと安全なコードは現在 `vuln`/`sec` ディレクトリに分離され、比較学習を容易にします。 |
| **豊富なリソースエコシステム** | APIドキュメント、脆弱性再現マニュアル、セキュアコーディング規約を内蔵し、CVEの最新脆弱性事例を継続的に更新します。 |
| **高い拡張性** | プラグイン式の脆弱性事例インターフェースを提供し、開発者がカスタマイズして新しい脆弱性シナリオを追加したり、防御策を拡張したりすることをサポートします。 |


## 🚀 クイックスタート
### 環境要件
- JDK 17 以上
- Maven 3.6+ または Gradle 8.0+
- Git（オプション、リポジトリのクローン用）
- Docker（オプション、コンテナ化デプロイ用）

### 方法1：ローカルMaven起動（初心者推奨）
```bash
# 1. リポジトリをクローン（または直接ZIPパッケージをダウンロード）
git clone --depth 1 https://github.com/XiaomingX/JSEF.git
cd JSEF

# 2. プロジェクトをビルド（テストをスキップしてビルドを高速化）
mvn clean package -DskipTests

# 3. サービスを起動
java -jar target/java-sec-code-plus-1.2.0.jar
```

### 方法2：Dockerワンクリックデプロイ
```bash
# 1. イメージをビルド
docker build -t jsef-security-sample:latest .

# 2. コンテナを起動
docker run -d -p 8080:8080 --name jsef-demo jsef-security-sample:latest
```

### デプロイ成功の検証
起動後、以下のアドレスにアクセスしてください：
- プロジェクトホームページ：`http://localhost:8080`（プロジェクトナビゲーションと脆弱性リストを確認）
- APIドキュメント（Swagger）：`http://localhost:8080/swagger-ui/index.html`（すべての脆弱性インターフェースの詳細を確認）
- 脆弱性マニュアル：`http://localhost:8080/docs`（オンラインの脆弱性再現ガイドを確認）


## 📋 脆弱性事例分類（35種類以上の完全リスト）
実装されているすべての脆弱性事例の詳細は、[VULNERABILITIES-jp.md](VULNERABILITIES-jp.md) を参照してください。

## 🎯 適用シナリオ
| ユーザー層 | 適用シナリオ |
|------------|----------------------|
| **開発エンジニア** | セキュアコーディング規約を学習し、プロジェクトで脆弱性のあるコードを記述するのを回避。 |
| **セキュリティリサーチャー** | 脆弱性の原理を再現し、防御策の有効性を検証し、セキュリティツールのテスト環境を構築。 |
| **大学生・教員** | 情報セキュリティ/ネットワークセキュリティの授業用実験プラットフォームとして、伝統的なデモ型実験に取って代わる。 |
| **企業研修** | 開発チームのセキュアコーディング研修、ペネトレーションテストチームの入門実践練習。 |
| **CTFプレイヤー** | 基本的な脆弱性の実践練習を行い、一般的な脆弱性の悪用手法を熟知。 |


## 🔬 SAST能力 および マルチモデル脆弱性発見 Benchmark

JSEF は教育プラットフォームであるだけでなく、**SAST 基礎能力の検証**と**複数 LLM の脆弱性発見能力の差の比較**に用いる benchmark を内蔵しています。設計は SAST の第一原理（source から sink への不信データ到達可能性の証明）に基づき、サンプルには判別力の勾配を持たせており、誤検出・見逃し・平均時間・タイムアウト・レポート簡潔さ・網羅性をクロス比較しやすくしています。

### コア能力

| 能力次元 | 説明 |
|---------|------|
| 汚染伝播（変数無断絶） | 単跳/多跳/間接（Map/フィールド）勾配、中間変数で汚染が落ちるか検証 |
| 状態機械 / 呼び出しチェーン追跡 | メソッド間/ファイル間/gadget chain、到達可能性解析の深さを検証 |
| フレームワーク意味理解 | Spring パラメータ束縛、SpEL、`@RequestParam` 駆動の暗黙的 source/sink |
| 誤検出抑制 | OWASP 式の真偽混同サンプル、「危険に見えるが安全」なコードの判別を検証 |

### サンプルと難易度グレード

サンプルは **L0-L5** にグレードされます（各レベルで推論距離と意味依存を増やし、ツール/モデルの差を引き離す；L0 は全ツール/モデルが命中すべき能力基準）：

| レベル | 意味 | 例 |
|------|------|------|
| L0 | 能力基準（明示的直結） | source が中間変数なしで sink に直結 |
| L1 | 単跳直結 | `Runtime.exec(userInput)` |
| L2 | 多跳（変数無断絶） | source -> 中間変数 -> builder -> sink |
| L3 | 間接 / メソッド間 | 汚染が Map/フィールド経由；メソッド戻り値で関数間越え |
| L4 | ファイル間 / フレームワーク意味 / 状態機械 | Controller -> ServiceA -> ServiceB -> sink；Spring4Shell SpEL 意味 |
| L5 | gadget chain | 複数の安全なクラスが組み合わさって危険な到達可能性に（CC 逆シリアライズチェーン抽象） |

基礎グレードに加え、LLM の**計画能力**と**一貫性**を検証するための「長期/複雑タスク」サンプル群が 2 つあります：
- **長期タスク（LT 系列）**：ファイル間追跡 / フレームワーク状態機械 / gadget chain 再構成 / 多跳連結 / バージョンゲート — 詳細は [`benchmark/README.md`](benchmark/README.md) §3。
- **コード品質 / 性能 DoS + LGTM 欠落（PERF/TB/REFLECT/FMT/HOST/XSLT/FWD/SEED 系列）**：スロー SQL、リソース漏洩、リフレクション注入、信頼境界、書式文字列注入など。LGTM/CodeQL Java ルールパックに準拠。

### 現在のサンプル規模

> データ出所：`benchmark/expectedresults.csv`（真実源、ソースの `// [CHECKPOINT]` 注釈と双方向一致；`validate_checkpoints.py` は終了コード 0）

- **782 件**の機械可読 checkpoint 注釈（`src/main` の既存脆弱性 + `benchmark/cases` 勾配サンプル + 長期タスク + コード品質/性能 DoS + LGTM 欠落 + 論理脆弱性サンプル + **原子パラダイム群 TCM/SBM/DBG/STR** + **シナリオ編成群（検出圧力/カスケード/複数脆弱性チェーン/活性分岐遮断）** を網羅）
- **414 件の VULN**（検出すべき） + **368 件の SAFE**（検出すべきでない、TN/FP 算出用）
- 難易度分布：L0 x 18、L1 x 165、L2 x 184、L3 x 181、L4 x 141、L5 x 93（完全な L0-L5 勾配）
- CWE カバー:**86 類**（VULN のみ）。上位：式注入(917)、逆シリアライズ(502)、SQLi(89)、コマンド注入(78)、認可回避(285)、ハードコード認証情報/鍵(798)、ビジネスロジック(840)、SSRF(918)、IDOR(639)、パストラバーサル(22)、ReDoS(1333)、性能 DoS(400)
- **189 カテゴリ**（slug）をカバー（OWASP Top 10 2021 全クラス含む）；**139 件**のサンプルが `trace=` パスノードを持つ（`--check-trace` パス正確性評価に対応）
- 専用サンプル群：長期タスク(LT) x 16、コード品質/性能 DoS(PERF) x 15、信頼境界(TB)/リフレクション(REFLECT)/書式文字列(FMT)/ホスト名(HOST)/XSLT(XSLT)/フォワード(FWD)/シード(SEED) 各 x 2
- **原子パラダイム群（TCM/SBM/DBG/STR）** x 64：Fastjson / Spring Boot / Dubbo / Struts2 の実際の 0day/1day から**ライブラリ非依存**の原子危険パラダイムを抽出し、純 Java 標準ライブラリのみで自前再現。以下の「原子パラダイム群」節参照。
- **シナリオ編成群（DE/OS/DEAD）** x 18：検出圧力（危険 sink は到達可能だが監視される、`detection-pressure`）、サービス間汚染（RestTemplate 往復、`cross-svc-taint`）、カスケード信頼（システム A の設定がシステム B の権限を決定、`cascade-trust`）、複数脆弱性チェーン（情報漏えい→特権昇格の連鎖、`multi-vuln-chain`）、活性分岐遮断（活性分岐が汚染を消毒し到達不能になる、`branch-dead-end`）。CyScenarioBench / FrontierCyber / Kimi K3 評価に対応。`plans/09-scenario-benchmark-orchestration-samples.md` 参照。

### 原子パラダイム群（TCM / SBM / DBG / STR）

LLM / harness が**同じ原理の**脆弱性を検出できるか評価するため、JSEF は近年の高影響フレームワーク（Fastjson / Spring Boot / Dubbo / Struts2）の 0day/1day から**ライブラリ非依存**の原子危険パラダイムを抽出し、元のフレームワークから切り離した同じ根因を持つ複雑なサンプルを構築します。各ファミリーは `vuln` + `sec` 対照（FP/TN 算出用）を備え、L1–L5 で格付けされ、すべて `// [CHECKPOINT]` 注釈を持ち、**元フレームワークのクラス名を含みません**（純標準ライブラリ意味論）。

| 名前空間 | 抽出元 | 原子パラダイム次元（MECE、重複なし） | サンプル数 |
|---------|--------|-------------------------------|--------|
| **TCM** | Fastjson 逆シリアライズ | TCM-1 直接型選択・TCM-2 継承許可リスト迂回・TCM-3 キャッシュ/再解析迂回・TCM-4 非公開フィールド束縛・TCM-5 プロパティ即コード（危険 getter/setter） | 20 |
| **SBM** | Spring Boot | SBM-1 バインダ走査・SBM-2 宣言的設定の式評価・SBM-3 高権限エンドポイント露出・SBM-4 認可ショートサーキット迂回 | 16 |
| **DBG** | Dubbo RPC | DBG-1 パーサ/フォーマット交渉切替・DBG-2 信頼境界越え暗黙的信用（attachment）・DBG-3 クラス名拒否リストの符号化迂回 | 16 |
| **STR** | Struts2/OGNL | STR-1 二重評価（Double Evaluation）・STR-2 プロトコル層フィールド注入・STR-3 式除外リスト/サンドボックス迂回 | 12 |

**設計要点**：
- 抽象化の原則：特定フレームワークの仕組み（例「JSON ライブラリ autotype」「Web フレームワーク SpEL」）を剥ぎ取り、フレームワークを越えた不変な危険結合——攻撃者が型/データを制御＋システムが暗黙的メソッドを自動呼び出し＋暗黙的メソッドチェーンが危険な sink に到達——のみを残す。
- 既存サンプルとの重複なし：既存の `JSEF-OGNL-*`/`JSEF-SPEL-*` 単層式注入、`JSEF-DESER-*` 直接逆シリアライズ等は意図的に避け、上記フレームワーク**独有かつ未モデル化**の原子次元（OGNL 二重評価、Spring4Shell バインダ走査、Dubbo パーサ交渉等）のみをカバー。
- 高い判別力：L4 跨ファイル、L5 gadget chain、跨メソッドチェーン等の難例を含み、ツール/モデルの能力階層を分離。
- 安全基線：すべての危険呼び出しは localhost デモ意味論・プレースホルダ文字列であり、実利用スクリプトは提供しない。

サンプル位置：`benchmark/cases/{vuln,sec}/{tcm,sbm,dbg,str}/`；設計文書：`plans/02-~05-*.md`。

サンプル構成：
- `benchmark/cases/vuln/` と `benchmark/cases/sec/`：判別力のある勾配サンプル（安全対照付き）
- `benchmark/cases/vuln/longtask/` と `benchmark/cases/vuln/perf/`：長期タスクとコード品質/性能 DoS 専用サンプル
- `benchmark/cases/vendor/`：OWASP Benchmark / Juliet / PrimeVul / CVEfixes から抽象した高品質競合サンプル（出所 URL 付き）

### 実行とクロス比較方法

1. JSEF 起動：`mvn clean package -DskipTests && java -jar target/*.jar`
2. 被験体選定：SAST ツール（CodeQL/SonarQube/Snyk）+ LLM（Claude Code でモデル切替、同一プロンプト `benchmark/prompts/vuln_hunt.md` 使用）
3. 各被験体が `benchmark/cases/` を一度走査し、SARIF または `id -> {hit,file,line}` 結果を出力、時間を記録
4. スコアリングスクリプトでクロス比較指標を算出（リポジトリルートで実行）：
   ```bash
   python3 benchmark/scripts/scorecard.py --expected benchmark/expectedresults.csv --result <result.json|.sarif> --name <被験体名>
   ```
   Recall / Precision / **Youden Score (TPR - FPR)** / 平均時間 / タイムアウト数 / レポート簡潔さ / 網羅性を、CWE とレベルでグループ化して出力。

詳細設計とプロトコルは [`benchmark/README.md`](benchmark/README.md) と [`MY_PLAN.md`](MY_PLAN.md) を参照。


## 📚 公式ドキュメント
- [📊 Benchmark 設計とプロトコル](benchmark/README.md)：SAST/LLM 脆弱性発見検収 benchmark の利用と拡張
- [🗺️ Benchmark 実装計画](MY_PLAN.md)：能力モデル、サンプルグレード、TODO進捗
- [📥 デプロイガイド](docs/deployment.md)：ローカル/Mac/Linux/Windows/Dockerでのデプロイ全案
- [🔍 脆弱性再現マニュアル](docs/vulnerability-guide.md)：各脆弱性の詳細な再現手順（Payload例含む）
- [💻 APIリファレンス](docs/api-reference.md)：すべてのインターフェースのリクエストパラメータとレスポンスフォーマットの説明（Swaggerオンラインデバッグをサポート）
- [🛡️ セキュアコーディングガイド](docs/secure-coding-guide.md)：Spring Bootベースのセキュアコーディングベストプラクティス
- [📌 新しい脆弱性事例の追加ガイド](docs/contribute-vulnerability.md)：プロジェクトに新しい脆弱性事例を追加する方法
- [🎥 動画チュートリアル](https://github.com/XiaomingX/JSEF/wiki/Video-Tutorials)：Bilibili（ビリビリ）対応の脆弱性再現動画（継続的に更新）


## 🤝 貢献方法
本プロジェクトはあらゆる形態の貢献を歓迎します。**新しい脆弱性事例の追加、ドキュメントの充実、コードの問題修正、機能提案**など、どのような支援でも多くの人がWebセキュリティを学ぶのを助けることができます！

### 貢献方法
1. **Issueの投稿**：脆弱性のフィードバック、機能提案、バグ報告を行う（事前に類似のIssueがないか検索することを推奨）
2. **PR（プルリクエスト）の投稿**：
   - コードの問題修正（スペルミス、ロジック最適化など）
   - 新しい脆弱性事例の追加（[新しい脆弱性事例の追加ガイド](docs/contribute-vulnerability.md)に従う必要があります）
   - ドキュメントの充実（再現手順の追加、英文ドキュメントの翻訳など）
3. **シェアと普及**：本プロジェクトにStarをつけ、技術コミュニティで使用体験を共有して、更多の人にJSEFを知ってもらう

### 初心者向け貢献
- [Good First Issues](https://github.com/XiaomingX/JSEF/issues?q=is%3Aopen+is%3Aissue+label%3A%22good+first+issue%22)：初心者に適した入門レベルのタスク（ドキュメントの補充、コードコメントの充実など）


## 📄 オープンソースライセンス
本プロジェクトは**MIT License**に基づいてオープンソース化されており、以下の使用を許可します：
- 個人の学習、企業研修、商用製品のテストに無料で使用
- プロジェクトコードの修正・配布（元の作者の著作権表示を保持する必要があります）
- 本プロジェクトに基づく二次開発（出典を明記する必要があります）

**禁止**：本プロジェクトを不正なペネトレーションテスト、悪意のある攻撃など違法行為に使用すること。


## ⭐ Star履歴
[![Star History Chart](https://api.star-history.com/svg?repos=XiaomingX/JSEF&type=Date)](https://star-history.com/#XiaomingX/JSEF&Date)


## 🙏 謝辞
- OWASP（https://owasp.org/）が提供するWebセキュリティ標準と脆弱性分類フレームワークに感謝
- Springコミュニティが提供するSpring Bootエコシステムのサポートに感謝
- すべての貢献者のコード投稿とフィードバックに感謝（[Contributors](https://github.com/XiaomingX/JSEF/graphs/contributors)）
- セキュリティコミュニティの技術ブロガーによる脆弱性原理の共有に感謝


## ⚠️ 免責事項
本プロジェクトは**学習、研究、企業内部のセキュリティ研修の目的にのみ使用**してください。不正なテスト、攻撃、破壊行為に使用しないでください。本プロジェクトの使用によって生じた一切の法的責任は、使用者が自己の責任で負うものとします。