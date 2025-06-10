#!/usr/bin/env python3
"""
simdscan.py – classify SIMD instructions by ISA extension.

$ ./simdscan.py path/to/binary
$ ./simdscan.py -f yaml --show-insts path/to/binary    # extra detail

Requires: GNU objdump (binutils), Python ≥3.8
"""

from __future__ import annotations
import argparse, json, re, subprocess, sys
from collections import Counter, defaultdict
from pathlib import Path
from textwrap import shorten

# ─────────────────────────  Instruction tables  ────────────────────────────────
# Format:  {ISA-name: {mnemonic1, mnemonic2, …}}
# Mnemonics must be lower-case, *without* the leading “v” for AVX encodings.
ISA_TABLE: dict[str, set[str]] = {
    # —— SSE family ——
    "SSE": {
        "addps",
        "addss",
        "andnps",
        "andps",
        "cmpps",
        "cmpss",
        "comiss",
        "cvtpi2ps",
        "cvtps2pi",
        "cvtsi2ss",
        "cvtss2si",
        "cvttps2pi",
        "cvttss2si",
        "divps",
        "divss",
        "ldmxcsr",
        "maxps",
        "maxss",
        "minps",
        "minss",
        "movaps",
        "movhlps",
        "movhps",
        "movlhps",
        "movlps",
        "movmskps",
        "movntps",
        "movss",
        "movups",
        "mulps",
        "mulss",
        "orps",
        "rcpps",
        "rcpss",
        "rsqrtps",
        "rsqrtss",
        "shufps",
        "sqrtps",
        "sqrtss",
        "stmxcsr",
        "subps",
        "subss",
        "ucomiss",
        "unpckhps",
        "unpcklps",
        "xorps",
        # MMX-with-SSE regs
        "pavgb",
        "pavgw",
        "pextrw",
        "pinsrw",
        "pmaxsw",
        "pmaxub",
        "pminsw",
        "pminub",
        "pmovmskb",
        "psadbw",
        "pshufw",
    },
    "SSE2": {
        "addpd",
        "addsd",
        "andnpd",
        "andpd",
        "cmppd",
        "comisd",
        "cvtdq2pd",
        "cvtdq2ps",
        "cvtpd2dq",
        "cvtpd2pi",
        "cvtpd2ps",
        "cvtpi2pd",
        "cvtps2dq",
        "cvtps2pd",
        "cvtsd2si",
        "cvtsd2ss",
        "cvtsi2sd",
        "cvtss2sd",
        "cvttpd2dq",
        "cvttpd2pi",
        "cvttps2dq",
        "cvttsd2si",
        "divpd",
        "divsd",
        "maxpd",
        "maxsd",
        "minpd",
        "minsd",
        "movapd",
        "movhpd",
        "movlpd",
        "movmskpd",
        "movupd",
        "mulpd",
        "mulsd",
        "orpd",
        "shufpd",
        "sqrtpd",
        "sqrtsd",
        "subpd",
        "subsd",
        "ucomisd",
        "unpckhpd",
        "unpcklpd",
        "xorpd",
        "movdq2q",
        "movdqa",
        "movdqu",
        "movq2dq",
        "paddq",
        "pmuludq",
        "pshufhw",
        "pshuflw",
        "pshufd",
        "pslldq",
        "psrldq",
        "punpckhqdq",
        "punpcklqdq",
    },
    "SSE3": {
        "addsubpd",
        "addsubps",
        "haddpd",
        "haddps",
        "hsubpd",
        "hsubps",
        "movddup",
        "movshdup",
        "movsldup",
        "lddqu",
        "fisttp",
    },
    "SSSE3": {
        "psignw",
        "psignd",
        "psignb",
        "pshufb",
        "pmulhrsw",
        "pmaddubsw",
        "phsubw",
        "phsubsw",
        "phsubd",
        "phaddw",
        "phaddsw",
        "phaddd",
        "palignr",
        "pabsw",
        "pabsd",
        "pabsb",
    },
    "SSE4": {
        # SSE4.1 + SSE4.2 + POPCNT/LZCNT/CRC32
        "mpsadbw",
        "phminposuw",
        "pmulld",
        "pmuldq",
        "dpps",
        "dppd",
        "blendps",
        "blendpd",
        "blendvps",
        "blendvpd",
        "pblendvb",
        "pblendw",
        "pblenddw",
        "pminsb",
        "pmaxsb",
        "pminuw",
        "pmaxuw",
        "pminud",
        "pmaxud",
        "pminsd",
        "pmaxsd",
        "roundps",
        "roundss",
        "roundpd",
        "roundsd",
        "insertps",
        "pinsrb",
        "pinsrd",
        "pinsrq",
        "extractps",
        "pextrb",
        "pextrd",
        "pextrw",
        "pextrq",
        "pmovsxbw",
        "pmovzxbw",
        "pmovsxbd",
        "pmovzxbd",
        "pmovsxbq",
        "pmovzxbq",
        "pmovsxwd",
        "pmovzxwd",
        "pmovsxwq",
        "pmovzxwq",
        "pmovsxdq",
        "pmovzxdq",
        "ptest",
        "pcmpeqq",
        "pcmpgtq",
        "packusdw",
        "pcmpestri",
        "pcmpestrm",
        "pcmpistri",
        "pcmpistrm",
        "crc32",
        "popcnt",
        "movntdqa",
        "extrq",
        "insertq",
        "movntsd",
        "movntss",
        "lzcnt",
    },
    # —— AVX family (scalar + packed). We lump AVX and AVX2 together here. ——
    "AVX": {
        # core three-operand forms (v-prefixed)
        "vaddps",
        "vaddpd",
        "vaddss",
        "vaddsd",
        "vsubps",
        "vsubpd",
        "vsubss",
        "vsubsd",
        "vmulps",
        "vmulpd",
        "vmulss",
        "vmulsd",
        "vdivps",
        "vdivpd",
        "vdivss",
        "vdivsd",
        "vmaxps",
        "vmaxpd",
        "vmaxss",
        "vmaxsd",
        "vminps",
        "vminpd",
        "vminss",
        "vminsd",
        "vxorps",
        "vxorpd",
        "vandps",
        "vandpd",
        # loads / stores / shuffles / blends
        "vmovaps",
        "vmovups",
        "vmovapd",
        "vmovupd",
        "vmovdqa",
        "vmovdqu",
        "vmovntps",
        "vmovntpd",
        "vbroadcastss",
        "vbroadcastsd",
        "vinsertf128",
        "vextractf128",
        "vblendps",
        "vblendpd",
        "vblendvps",
        "vblendvpd",
        "vpermilps",
        "vpermilpd",
        "vperm2f128",
        "vshufps",
        "vshufpd",
        "vzeroupper",
        # integer AVX2 subset (256-bit)
        "vpaddd",
        "vpsubd",
        "vpmulld",
        "vpmuludq",
        "vpackssdw",
        "vpackusdw",
        "vpcmpeqd",
        "vpcmpgtd",
        "vpminud",
        "vpmaxud",
        "vpminsd",
        "vpmaxsd",
        # gather/mask instructions (AVX2/AVX-512VL)
        "vgatherdps",
        "vgatherdpd",
        "vpgatherdd",
        "vpgatherdq",
        "vpmaskmovd",
        "vpmaskmovq",
        "vmaskmovps",
        "vmaskmovpd",
        # FMA (FMA3)
        "vfmadd213pd",
        "vfmadd231pd",
        "vfmadd132pd",
        "vfmsub213pd",
        "vfmsub231pd",
        "vfmsub132pd",
        "vfnmadd213pd",
        "vfnmadd231pd",
        "vfnmadd132pd",
        # others …
    },
    # —— AVX-512 (any flavour counts as AVX-512 use) ——
    "AVX-512": {
        # We only need a *few* unique mnemonics or zmm/k usage to flag AVX-512.
        # Example core integer / FP ops:
        "vaddps",
        "vaddpd",
        "vsubps",
        "vsubpd",
        "vmaxps",
        "vmaxpd",  # zmm form
        "kaddd",
        "kandd",
        "korw",
        "kxorq",  # mask regs
        "vcompresspd",
        "vexpandps",
        "vpermb",
        "vpmovm2d",
        "vpconflictd",
        "vpternlogd",
        "vpshldv",
        "vpopcntd",
        "vscalefpd",
        "vrndscaleps",
    },
}

# Pre-compile regex set for performance ----------------------------------------
# We detect an instruction line by:
#   (optional whitespace)(hex addr): <tab> mnemonic   (% or $ operands …)
OBJLINE_RE = re.compile(r"^\s*[0-9a-f]+:\s+\w")  # cheap early filter
# Extract the mnemonic (first whitespace-delimited token after possible "v")
MNE_RE = re.compile(r"\s([a-z][a-z0-9]+\b)")


def disassemble(path: Path) -> list[str]:
    """Return list of lines from objdump -d output (raises on error)."""
    try:
        out = subprocess.check_output(
            ["objdump", "-d", "--no-show-raw-insn", str(path)],
            text=True,
            stderr=subprocess.STDOUT,
        )
    except subprocess.CalledProcessError as e:
        sys.stderr.write(e.output)
        sys.exit(f"[error] objdump failed ({e.returncode})")
    return out.splitlines()


def classify(lines: list[str]) -> tuple[Counter, dict[str, Counter]]:
    """
    Returns:
        isa_counts   – Counter{ISA ⇒ occurrences}
        inst_detail  – {ISA ⇒ Counter{mnemonic ⇒ occurrences}}
    """
    isa_counts: Counter[str] = Counter()
    inst_detail: dict[str, Counter] = defaultdict(Counter)

    for ln in lines:
        if not OBJLINE_RE.match(ln):  # skip non-instruction lines early
            continue
        m = MNE_RE.search(ln)
        if not m:
            continue
        mnem = m.group(1).lower()

        # fast path: check each ISA table
        for isa, mset in ISA_TABLE.items():
            if mnem in mset:
                isa_counts[isa] += 1
                inst_detail[isa][mnem] += 1
                # Stop at first match: an instruction belongs to exactly one table
                break

    return isa_counts, inst_detail


# ─────────────────────────────  CLI / I/O  ─────────────────────────────────────
def parse_args():
    ap = argparse.ArgumentParser(
        description="Detect SIMD instructions and classify by ISA extension."
    )
    ap.add_argument("binary", type=Path, help="ELF / Mach-O / PE (x86-64)")
    ap.add_argument(
        "-f",
        "--format",
        choices=["json", "yaml"],
        default="json",
        help="output format (default json)",
    )
    ap.add_argument(
        "--show-insts",
        action="store_true",
        help="include per-ISA instruction breakdown",
    )
    return ap.parse_args()


def main() -> None:
    args = parse_args()
    if not args.binary.exists():
        sys.exit(f"[error] {args.binary} not found")

    lines = disassemble(args.binary)
    isa_counts, inst_detail = classify(lines)

    # Build structured report ---------------------------------------------------
    report = {
        "binary": str(args.binary),
        "has_simd": bool(isa_counts),
        "isa_summary": dict(sorted(isa_counts.items(), key=lambda kv: kv[0])),
        "total_simd_insts": sum(isa_counts.values()),
    }

    if args.show_insts:
        report["isa_details"] = {
            isa: {
                "unique_mnemonics": len(detail),
                "occurrences": dict(detail.most_common(10)),  # top-10 for brevity
            }
            for isa, detail in inst_detail.items()
        }

    # Emit ----------------------------------------------------------------------
    if args.format == "yaml":
        try:
            import yaml

            print(yaml.dump(report, sort_keys=False, allow_unicode=True))
        except ModuleNotFoundError:
            sys.exit("[error] PyYAML not installed – choose JSON or install PyYAML")
    else:
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
