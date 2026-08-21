#!/usr/bin/env python3
"""JSEF Benchmark — 模型无关通用 LLM 评测 runner（HTTP 直连）。

以 CSV 的「文件」为单位，通过 OpenAI / Anthropic 兼容的 HTTP API 驱动**任意**大语言
模型做漏洞挖掘，把输出解析并对齐到 sample id，落盘为 scorecard 能读取的 result.json
（identify 模式）或 *.sarif（blind 模式）。支持断点续跑、分层子集、超时保护、覆盖率闸门。

与 run_mimofan_benchmark.py 的区别
----------------------------------
- 本脚本**不依赖本地 mimofan 二进制**，直接 requests 调 HTTP API，模型无关：
  换 GLM-5.3 / Mythos / GPT / DeepSeek 等任意 OpenAI/Anthropic 兼容端点只需换
  --provider / --base-url / --model / --api-key。
- 复用 run_mimofan 的成熟逻辑：prompt 构造、强容错 JSON 解析、断点续跑、单文件错误隔离、
  覆盖率闸门。

用法
----
  # 判别式（identify，默认）：列出 sample id 让模型逐条判定 → 算「做题正确率」
  python3 run_llm_benchmark.py \
      --provider openai --base-url https://open.bigmodel.cn/api/paas/v4 \
      --model glm-5.3 --api-key $BIGMODEL_KEY --name glm-5.3

  # 盲挖式（blind）：不泄 ground truth，让模型自行报漏洞 → 测严格发现能力
  python3 run_llm_benchmark.py \
      --provider anthropic --base-url https://api.anthropic.com \
      --model mythos-5 --api-key $ANTHROPIC_KEY --name mythos-5 --mode blind

  python3 run_llm_benchmark.py --resume       # 只跑未完成文件
  python3 run_llm_benchmark.py --only-level L0,L1,L2
  python3 run_llm_benchmark.py --limit 10     # 调试：只跑前 N 个文件
  python3 run_llm_benchmark.py --dry-run      # 只打印将跑的文件，不调用 API

环境变量
--------
  OPENAI_API_KEY      --provider openai 时若未给 --api-key 则读取
  ANTHROPIC_API_KEY   --provider anthropic 时若未给 --api-key 则读取
"""
import argparse
import csv
import json
import os
import re
import sys
import threading
import time

import requests

ROOT = os.path.dirname(os.path.abspath(__file__))
EXPECTED = os.path.join(ROOT, "benchmark", "expectedresults.csv")
RESULTS_BASE = os.path.join(ROOT, "benchmark", "results")
TIMEOUT_S = 120       # JSEF 单样本超时阈值（秒）
MAX_TOKENS = 4096     # 模型输出上限
MAX_RETRIES = 3       # 429/5xx 指数退避重试次数


# --------------------------------------------------------------------------- #
# 事实源加载（与 run_mimofan 一致）
# --------------------------------------------------------------------------- #
def load_expected():
    samples = []
    with open(EXPECTED, newline="", encoding="utf-8-sig") as fh:
        for row in csv.DictReader(fh):
            samples.append({
                "id": row["id"].strip(),
                "cwe": row["cwe"].strip(),
                "level": row["level"].strip(),
                "type": row["type"].strip().lower(),
                "file": row["file"].strip(),
                "line": int(row["line"]) if row["line"].strip().isdigit() else -1,
            })
    return samples


def aggregate_by_file(samples):
    by_file = {}
    for s in samples:
        by_file.setdefault(s["file"], []).append(s)
    return by_file


# --------------------------------------------------------------------------- #
# Prompt 构造
# --------------------------------------------------------------------------- #
def build_identify_prompt(file_path, file_samples):
    """判别式：列出该文件所有 expected sample id，要求逐条 hit 判定。"""
    lines = []
    lines.append("你是一名 Java 静态应用安全测试（SAST）专家。请对下面给定的 Java 源码文件做漏洞挖掘，")
    lines.append("识别其中真实存在的安全缺陷（true positive），不要对'看似危险但实际安全'的代码误报。")
    lines.append("")
    lines.append("分析该文件，并针对我列出的每个 sample id 给出判定：")
    lines.append("- 若该 id 对应代码经你判断确为真实漏洞，输出 {id, hit:true, line:<精确行号>, cwe:<CWE编号>, message:<一句话成因+修复建议>}。")
    lines.append("- 若该 id 对应代码经你判断是安全的（对照实现/已加固），输出 {id, hit:false, line:<该代码行号>, cwe:<CWE编号>, message:<为何安全>}。")
    lines.append("- 不要为未在列表中的 id 编造条目；若你发现列表中未覆盖的真实漏洞，可额外附一条 {id:'EXTRA', hit:true, ...}（不计入评分但供参考）。")
    lines.append("- 只输出一个 JSON 列表，不要 markdown 代码块标记、不要任何解释文字。")
    lines.append("")
    lines.append("待分析文件绝对路径：%s" % file_path)
    lines.append("")
    lines.append("需逐条判定的 sample id 清单：")
    for s in file_samples:
        lines.append("  - id=%s | 期望CWE=CWE-%s | 标注行=%d | 类型=%s"
                     % (s["id"], s["cwe"], s["line"], s["type"]))
    return "\n".join(lines)


def build_blind_prompt(file_path, file_samples):
    """盲挖式：不泄 ground truth，仅给文件与输出格式约定（vuln_hunt.md §3.1）。"""
    prompt_file = os.path.join(ROOT, "benchmark", "prompts", "vuln_hunt.md")
    if os.path.isfile(prompt_file):
        with open(prompt_file, encoding="utf-8") as fh:
            base = fh.read()
    else:
        base = ("你是一名 Java 静态应用安全测试（SAST）专家。对给定 Java 源码做漏洞挖掘，"
                "报告真实存在的安全缺陷。输出符合 SARIF 2.1.0 的 JSON：\n"
                "{\"version\":\"2.1.0\",\"runs\":[{\"tool\":{\"driver\":{\"name\":\"<模型名>\"}},"
                "\"results\":[{\"ruleId\":\"CWE-xxx\",\"level\":\"error\",\"message\":{\"text\":\"<成因+修复>\"},"
                "\"locations\":[{\"physicalLocation\":{\"artifactLocation\":{\"uri\":\"<相对仓库根路径>\"},"
                "\"region\":{\"startLine\":<精确行号>}}}]}]}]}\n"
                "只输出这个 SARIF JSON，不要额外解释。")
    # 追加本次要分析的文件
    lines = [base, "", "待分析文件绝对路径：%s" % file_path,
             "请以该文件为范围输出 SARIF 结果（ruleId 用 CWE 编号，startLine 为精确行号）。"]
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# HTTP 协议抽象（OpenAI 兼容 vs Anthropic 兼容）
# --------------------------------------------------------------------------- #
def _openai_request(base_url, api_key, model, system, user, max_tokens, timeout_s):
    url = base_url.rstrip("/") + "/chat/completions"
    headers = {"Authorization": "Bearer " + api_key, "Content-Type": "application/json"}
    payload = {
        "model": model,
        "messages": [{"role": "system", "content": system},
                     {"role": "user", "content": user}],
        "max_tokens": max_tokens,
        "stream": False,
    }
    resp = requests.post(url, headers=headers, json=payload, timeout=timeout_s)
    resp.raise_for_status()
    data = resp.json()
    content = ""
    truncated = False
    try:
        content = data["choices"][0]["message"]["content"] or ""
    except (KeyError, IndexError, TypeError):
        content = ""
    try:
        truncated = data["choices"][0].get("finish_reason") == "length"
    except (KeyError, IndexError, TypeError):
        truncated = False
    return content, truncated


def _anthropic_request(base_url, api_key, model, system, user, max_tokens, timeout_s):
    url = base_url.rstrip("/") + "/messages"
    headers = {
        "x-api-key": api_key,
        "anthropic-version": "2023-06-01",
        "Content-Type": "application/json",
    }
    payload = {
        "model": model,
        "max_tokens": max_tokens,
        "system": system,
        "messages": [{"role": "user", "content": user}],
        "stream": False,
    }
    resp = requests.post(url, headers=headers, json=payload, timeout=timeout_s)
    resp.raise_for_status()
    data = resp.json()
    content = ""
    truncated = False
    try:
        content = "".join(b.get("text", "") for b in data.get("content", [])
                          if isinstance(b, dict))
    except (TypeError, KeyError):
        content = ""
    try:
        truncated = data.get("stop_reason") == "max_tokens"
    except TypeError:
        truncated = False
    return content, truncated


def call_llm(provider, base_url, api_key, model, system, user,
             timeout_s=TIMEOUT_S, max_tokens=MAX_TOKENS, max_retries=MAX_RETRIES):
    """统一调用：返回 (text, elapsed_ms, timed_out, truncated)。带指数退避重试。"""
    request_fn = _openai_request if provider == "openai" else _anthropic_request
    for attempt in range(max_retries + 1):
        t0 = time.time()
        timed_out = False
        try:
            text, truncated = request_fn(
                base_url, api_key, model, system, user, max_tokens, timeout_s)
            elapsed = int((time.time() - t0) * 1000)
            return text, elapsed, False, truncated
        except requests.exceptions.Timeout:
            timed_out = True
            elapsed = int((time.time() - t0) * 1000)
            if attempt == max_retries:
                return "", elapsed, True, False
            sys.stderr.write("    [retry %d] 超时，%ds 后重试\n" % (attempt + 1, timeout_s))
            time.sleep(timeout_s)
        except requests.exceptions.HTTPError as exc:
            code = exc.response.status_code if exc.response is not None else 0
            if code in (429, 500, 502, 503, 504) and attempt < max_retries:
                backoff = 2 ** attempt
                sys.stderr.write("    [retry %d] HTTP %d，%ds 后重试\n" % (attempt + 1, code, backoff))
                time.sleep(backoff)
                continue
            raise
        except requests.exceptions.RequestException:
            elapsed = int((time.time() - t0) * 1000)
            if attempt == max_retries:
                raise
            time.sleep(2 ** attempt)
    return "", int((time.time() - t0) * 1000), False, False


# --------------------------------------------------------------------------- #
# 结果解析与对齐（移植 run_mimofan）
# --------------------------------------------------------------------------- #
def extract_json_array(text):
    """强容错提取 JSON 数组（identify 模式）。"""
    text = re.sub(r"```(?:json)?", "", text).strip()
    if text.startswith("[") and text.endswith("]"):
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass
    start = text.find("[")
    end = text.rfind("]")
    if start != -1 and end != -1 and end > start:
        snippet = text[start:end + 1]
        try:
            return json.loads(snippet)
        except json.JSONDecodeError:
            pass
    objs = []
    for m in re.finditer(r"\{[^{}]*\}", text):
        try:
            objs.append(json.loads(m.group(0)))
        except json.JSONDecodeError:
            continue
    if objs:
        return objs
    return None


def extract_sarif(text):
    """强容错提取 SARIF JSON（blind 模式）。"""
    text = re.sub(r"```(?:json)?", "", text).strip()
    candidates = [text]
    start, end = text.find("{"), text.rfind("}")
    if start != -1 and end != -1 and end > start:
        candidates.insert(0, text[start:end + 1])
    for c in candidates:
        try:
            return json.loads(c)
        except json.JSONDecodeError:
            continue
    return None


def map_results(file_samples, parsed, file_rel, elapsed, timed_out):
    """identify 模式：把模型输出按 id 映射到 expected sample。"""
    by_id = {s["id"]: s for s in file_samples}
    reported = {}
    if isinstance(parsed, list):
        for item in parsed:
            if not isinstance(item, dict):
                continue
            sid = str(item.get("id", "")).strip()
            if sid in by_id:
                reported[sid] = {
                    "id": sid,
                    "hit": bool(item.get("hit", False)),
                    "file": file_rel,
                    "line": int(item.get("line", by_id[sid]["line"])) if str(item.get("line", "")).strip().isdigit() else by_id[sid]["line"],
                    "cwe": "CWE-%s" % by_id[sid]["cwe"],
                    "message": str(item.get("message", "")),
                    "elapsed_ms": elapsed,
                }
    results = list(reported.values())
    for s in file_samples:
        if s["id"] not in reported:
            if timed_out:
                continue
            if s["type"] == "vuln":
                results.append({
                    "id": s["id"], "hit": False, "file": file_rel,
                    "line": s["line"], "cwe": "CWE-%s" % s["cwe"],
                    "message": "(未产出：模型未覆盖/超时)", "elapsed_ms": elapsed,
                })
            # safe 未报 = 正确，不写入
    return results


def to_sarif(file_rel, parsed):
    """blind 模式：把模型 SARIF 解析结果规范化为可写文件。"""
    if not isinstance(parsed, dict):
        return None
    # 规范化：确保 ruleId 为 CWE 编号、uri 相对仓库根
    runs = parsed.get("runs") or []
    results = []
    for run in runs:
        for res in (run.get("results") or []):
            rule = str(res.get("ruleId", "CWE-OTHER"))
            locs = res.get("locations") or []
            if not locs:
                continue
            uri = locs[0].get("physicalLocation", {}).get("artifactLocation", {}).get("uri", file_rel)
            line = locs[0].get("physicalLocation", {}).get("region", {}).get("startLine", 0)
            results.append({
                "ruleId": rule,
                "level": res.get("level", "error"),
                "message": {"text": (res.get("message") or {}).get("text", "")},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {"startLine": line}}},
                ],
            })
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{"tool": {"driver": {"name": "llm-runner"}}, "results": results}],
    }


# --------------------------------------------------------------------------- #
# 断点续跑 / 覆盖率闸门（移植 run_mimofan）
# --------------------------------------------------------------------------- #
def _done_file(out_dir):
    return os.path.join(out_dir, ".done.txt")


def load_done(out_dir):
    df = _done_file(out_dir)
    if os.path.isfile(df):
        with open(df, encoding="utf-8") as fh:
            return set(l.strip() for l in fh if l.strip())
    return set()


def save_done(out_dir, done):
    os.makedirs(out_dir, exist_ok=True)
    with open(_done_file(out_dir), "w", encoding="utf-8") as fh:
        for f in sorted(done):
            fh.write(f + "\n")


# --------------------------------------------------------------------------- #
# 主流程
# --------------------------------------------------------------------------- #
def main():
    ap = argparse.ArgumentParser(description="模型无关通用 LLM 评测 runner（HTTP 直连）")
    ap.add_argument("--provider", choices=["openai", "anthropic"], default="openai")
    ap.add_argument("--base-url", required=True, help="API 基础 URL，如 https://open.bigmodel.cn/api/paas/v4")
    ap.add_argument("--model", required=True, help="模型标识，如 glm-5.3 / mythos-5 / gpt-5.6")
    ap.add_argument("--api-key", default=None, help="鉴权令牌；缺省读 OPENAI_API_KEY / ANTHROPIC_API_KEY")
    ap.add_argument("--name", default=None, help="结果对象名（目录名 benchmark/results/<name>/）；默认取 model")
    ap.add_argument("--mode", choices=["identify", "blind"], default="identify",
                    help="identify=判别式(默认,算做题正确率) / blind=盲挖式(不泄ground truth,测发现能力)")
    ap.add_argument("--resume", action="store_true")
    ap.add_argument("--only-level", help="逗号分隔 level 过滤，如 L0,L1,L2")
    ap.add_argument("--only-namespace", help="逗号分隔 id 前缀过滤，如 tcm,sbm,dbg,str")
    ap.add_argument("--only-file", help="只跑指定相对路径文件")
    ap.add_argument("--only-type", help="逗号分隔 type 过滤，vuln/safe")
    ap.add_argument("--limit", type=int, help="只跑前 N 个文件")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--timeout", type=int, default=TIMEOUT_S)
    ap.add_argument("--max-tokens", type=int, default=MAX_TOKENS)
    ap.add_argument("--require-complete", dest="require_complete", action="store_true",
                    default=True,
                    help="默认开启：覆盖率不足 100%% 则以 exit 2 中止，防止截断被误判为完整")
    ap.add_argument("--no-require-complete", dest="require_complete", action="store_false",
                    help="调试用：允许截断运行")
    ap.add_argument("--trials", type=int, default=1,
                    help="同一批文件跑 N 次独立试验，写入 <name>/trial_i/result.json（借鉴 DeepSWE N-trial 稳定性）")
    args = ap.parse_args()

    # API key 解析
    api_key = args.api_key
    if not api_key:
        env_key = "ANTHROPIC_API_KEY" if args.provider == "anthropic" else "OPENAI_API_KEY"
        api_key = os.environ.get(env_key, "")
    if not api_key:
        sys.stderr.write("[FATAL] 缺少 api-key：请用 --api-key 或环境变量 %s\n"
                         % ("ANTHROPIC_API_KEY" if args.provider == "anthropic" else "OPENAI_API_KEY"))
        sys.exit(2)

    object_name = args.name or args.model
    out_dir = os.path.join(RESULTS_BASE, object_name)

    samples = load_expected()
    by_file = aggregate_by_file(samples)

    # 过滤（宽 OR，文件含任一满足 sample 即整文件入选）
    levels = set((args.only_level or "").upper().split(",")) - {""}
    nses = set((args.only_namespace or "").lower().split(",")) - {""}
    types = set((args.only_type or "").lower().split(",")) - {""}
    selected = {}
    for f, fs in by_file.items():
        if args.only_file and f != args.only_file:
            continue
        if levels or nses or types:
            keep = []
            for s in fs:
                ok = False
                if levels and s["level"] in levels:
                    ok = True
                if nses and any(s["id"].lower().startswith("jsef-" + n) for n in nses):
                    ok = True
                if types and s["type"] in types:
                    ok = True
                if ok:
                    keep.append(s)
            if not keep:
                continue
            selected[f] = keep
        else:
            selected[f] = fs

    if args.limit:
        selected = dict(list(selected.items())[:args.limit])

    trials_n = args.trials if args.trials >= 1 else 1

    if args.dry_run:
        # 预计算待跑清单（首个 trial 或单次）
        _out_dir, _ = _trial_target(out_dir, 1, trials_n)
        _done = load_done(_out_dir) if args.resume else set()
        _todo = [f for f in selected if f not in _done]
        for f in _todo:
            print("  WOULD RUN:", f, "(%d samples)" % len(selected[f]))
        return

    # trials 模式：外层循环 N 次，每次独立 out_dir/result_file/done
    for trial_idx in range(1, trials_n + 1):
        trial_out_dir, trial_result_file = _trial_target(out_dir, trial_idx, trials_n)
        _run_sweep(args, api_key, selected, object_name,
                   trial_out_dir, trial_result_file)
        # 写伴生 meta.json（成本/步数维度，可选占位）
        if trials_n > 1:
            _write_meta(trial_out_dir, args, trial_idx)

    if trials_n <= 1:
        print("[done] 结果目录: %s" % out_dir)


def _trial_target(base_out_dir, trial_idx, trials_n):
    """返回 (out_dir, result_file)：单次返回原路径；trials 返回 trial_i/ 下路径。"""
    if trials_n <= 1:
        return base_out_dir, os.path.join(base_out_dir, "result.json")
    tdir = os.path.join(base_out_dir, "trial_%d" % trial_idx)
    return tdir, os.path.join(tdir, "result.json")


def _write_meta(trial_out_dir, args, trial_idx):
    """写伴生 meta.json（agent 步数/成本，供 compare_models 展示；无真实值用占位）。"""
    meta = {
        "model": args.model,
        "trial": trial_idx,
        # 以下为可选项：runner 目前未追踪真实 agent 步数/成本，缺省 None；
        # 用户在真实调用后可手动补充，compare_models 会读取展示。
        "steps": None,
        "cost_usd": None,
        "input_tokens": None,
        "output_tokens": None,
    }
    try:
        os.makedirs(trial_out_dir, exist_ok=True)
        with open(os.path.join(trial_out_dir, "meta.json"), "w", encoding="utf-8") as fh:
            json.dump(meta, fh, indent=2, ensure_ascii=False)
    except OSError:
        pass


def _run_sweep(args, api_key, selected, object_name, out_dir, result_file):
    """对一批文件做一次完整 sweep（identify 或 blind），写结果到 out_dir/result_file。"""
    done = load_done(out_dir) if args.resume else set()
    todo = [f for f in selected if f not in done]

    print("[info] provider=%s model=%s mode=%s trial_out=%s 待跑=%d"
          % (args.provider, args.model, args.mode,
             os.path.relpath(out_dir, RESULTS_BASE), len(todo)))

    os.makedirs(out_dir, exist_ok=True)

    if args.mode == "identify":
        all_results = []
        if os.path.isfile(result_file) and args.resume:
            try:
                with open(result_file, encoding="utf-8") as fh:
                    all_results = json.load(fh)
            except Exception:
                all_results = []
        for i, f in enumerate(todo, 1):
            fs = selected[f]
            fabs = os.path.join(ROOT, f)
            if not os.path.isfile(fabs):
                sys.stderr.write("[skip] 文件不存在: %s\n" % f)
                done.add(f)
                continue
            try:
                prompt = build_identify_prompt(fabs, fs)
                sys.stderr.write("[%d/%d] %s (%d samples) ...\n" % (i, len(todo), f, len(fs)))
                text, elapsed, timed_out, truncated = call_llm(
                    args.provider, args.base_url, api_key, args.model,
                    "你是 JSEF 漏洞挖掘评测助手，只输出要求的 JSON。", prompt,
                    args.timeout, args.max_tokens)
                if truncated:
                    sys.stderr.write("    [warn] 输出被 max_tokens 截断\n")
                parsed = extract_json_array(text) if text else None
                if parsed is None:
                    sys.stderr.write("    [warn] 解析失败/超时，视为该文件全部未报\n")
                    parsed = []
                results = map_results(fs, parsed, f, elapsed, timed_out)
                all_results.extend(results)
                done.add(f)
                with open(result_file, "w", encoding="utf-8") as fh:
                    json.dump(all_results, fh, indent=2, ensure_ascii=False)
                save_done(out_dir, done)
                sys.stderr.write("    ok: %d 条结果, elapsed=%dms, timeout=%s\n"
                                 % (len(results), elapsed, timed_out))
            except Exception as exc:  # noqa: BLE001 — 单文件失败不应拖垮整轮
                sys.stderr.write("    [ERROR] 文件 %s 处理异常: %s\n" % (f, exc))
                continue
    else:  # blind：每文件产出一个 .sarif
        for i, f in enumerate(todo, 1):
            fs = selected[f]
            fabs = os.path.join(ROOT, f)
            if not os.path.isfile(fabs):
                sys.stderr.write("[skip] 文件不存在: %s\n" % f)
                done.add(f)
                continue
            sarif_path = os.path.join(out_dir, f.replace("/", "__").replace(".java", ".sarif"))
            try:
                prompt = build_blind_prompt(fabs, fs)
                sys.stderr.write("[%d/%d] %s (blind) ...\n" % (i, len(todo), f))
                text, elapsed, timed_out, truncated = call_llm(
                    args.provider, args.base_url, api_key, args.model,
                    "", prompt, args.timeout, args.max_tokens)
                if truncated:
                    sys.stderr.write("    [warn] 输出被 max_tokens 截断\n")
                parsed = extract_sarif(text) if text else None
                sarif = to_sarif(f, parsed)
                if sarif is None:
                    sys.stderr.write("    [warn] SARIF 解析失败/超时，写出空 SARIF\n")
                    sarif = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": object_name}}, "results": []}]}
                with open(sarif_path, "w", encoding="utf-8") as fh:
                    json.dump(sarif, fh, indent=2, ensure_ascii=False)
                done.add(f)
                save_done(out_dir, done)
                sys.stderr.write("    ok: SARIF 已写出, elapsed=%dms, timeout=%s\n" % (elapsed, timed_out))
            except Exception as exc:  # noqa: BLE001
                sys.stderr.write("    [ERROR] 文件 %s 处理异常: %s\n" % (f, exc))
                continue

    done_in_selected = len(done & set(selected))
    coverage = done_in_selected / len(selected) if selected else 1.0
    print("[SUMMARY] 选中=%d 已完成=%d 覆盖率=%.1f%%" % (len(selected), done_in_selected, coverage * 100))

    if done_in_selected < len(selected):
        sys.stderr.write(
            "\n[WARN] 截断运行！仅 %d/%d 文件完成（覆盖率 %.1f%%）。\n"
            "        未完成的文件不会被写入，其 vuln 样本会被 scorecard 误判为 FN。\n"
            "        请重新运行（加 --resume）直到覆盖率为 100%% 再跑 scorecard。\n"
            % (done_in_selected, len(selected), coverage * 100))
        if args.require_complete:
            sys.stderr.write("[FATAL] --require-complete 已设：因覆盖不足而中止（exit 2）。\n")
            sys.exit(2)


if __name__ == "__main__":
    main()
