#!/usr/bin/env python3
"""Summarize complete ASIACCS27 raw sample JSONL files into CSV."""
import argparse, glob, json, math, statistics, sys

def quantile(xs,p):
    ys=sorted(xs); pos=(len(ys)-1)*p; lo=math.floor(pos); hi=math.ceil(pos)
    return ys[lo] if lo==hi else ys[lo]*(hi-pos)+ys[hi]*(pos-lo)

parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument("out", nargs="?", default="docs/benchmarks/asiaccs27-20261116/summary.csv",
                    help="CSV output path")
out=parser.parse_args().out
files=glob.glob("docs/benchmarks/asiaccs27-20261116/release-*.jsonl")
rows=[]
timed=("prove_ns","proof_total_ns","commitments_ns","other_proof_ns",
       "nonce_aggregation_ns","share_verification_ns","response_aggregation_ns",
       "serial_end_to_end_ns","certificate_verify_ns","verify_v1_ns",
       "verify_folding_scalars_ns","verify_v2_msm_ns","verify_schnorr_equation_ns",
       "full_verify_ns","signer_round1_ns","signer_cert_verify_ns",
       "signer_nonce_generation_ns","signer_round2_ns","mode1_signer_round1_ns",
       "mode1_cert_verify_ns","mode1_linkage_ns","mode1_nonce_generation_ns",
       "mode1_signer_round2_ns")
sizes=("certificate_bytes","signature_bytes","round1_request_bytes",
       "mode1_round1_request_bytes","round1_response_bytes","mode1_round1_response_bytes",
       "round2_request_bytes","round2_response_bytes","mode1_round2_response_bytes")
for path in files:
    data=[json.loads(line) for line in open(path) if line.strip()]
    if not data: continue
    if any(key not in data[0] for key in ("n","t","r")):
        print(f"skip non-protocol run: {path}",file=sys.stderr); continue
    if len(data)<100: print(f"skip incomplete: {path} ({len(data)}/100)",file=sys.stderr); continue
    for key in ("n","t","r"):
        if any(d[key]!=data[0][key] for d in data): raise ValueError(f"mixed {key}: {path}")
    required=timed+sizes+("fold_round_ns",)
    if any(any(col not in d for col in required) for d in data):
        print(f"skip outdated schema: {path}",file=sys.stderr); continue
    if any(len(d["fold_round_ns"])!=data[0]["r"] for d in data):
        raise ValueError(f"fold-round count mismatch: {path}")
    n=data[0]["n"]; r=data[0]["r"]
    ell=n.bit_length(); kappa=(n+ell-1).bit_length(); N=1<<kappa
    h=N>>r
    analytic_signature=33*(7+2*r)+32*(5+2*h)
    row={"source":path,"n":n,"t":data[0]["t"],"r":r,"N":N,"kappa":kappa,
         "analytic_certificate_bytes":analytic_signature-98,
         "analytic_signature_bytes":analytic_signature,
         "analytic_public_parameters_bytes":33*(n+2*N+3),"samples":len(data)}
    fold_totals=[sum(d["fold_round_ns"]) for d in data]
    for col in timed+sizes+("folding_total_ns",):
        vals=fold_totals if col=="folding_total_ns" else [d[col] for d in data]
        row[col+"_median"]=statistics.median(vals)
        row[col+"_q1"]=quantile(vals,.25);row[col+"_q3"]=quantile(vals,.75)
        if col.endswith("_ns"):
            row[col+"_p95"]=quantile(vals,.95)
    serial_total=[d["serial_end_to_end_ns"]+d["full_verify_ns"] for d in data]
    row["serial_total_ns_median"]=statistics.median(serial_total)
    row["serial_total_ns_q1"]=quantile(serial_total,.25)
    row["serial_total_ns_q3"]=quantile(serial_total,.75)
    row["serial_total_ns_p95"]=quantile(serial_total,.95)
    for j in range(data[0]["r"]):
        vals=[d["fold_round_ns"][j] for d in data]
        key=f"fold_round_{j}_ns"
        row[key+"_median"]=statistics.median(vals)
        row[key+"_q1"]=quantile(vals,.25);row[key+"_q3"]=quantile(vals,.75)
        row[key+"_p95"]=quantile(vals,.95)
    rows.append(row)
if rows:
    cols=list(dict.fromkeys(col for row in rows for col in row))
    with open(out,"w") as f:
        f.write(",".join(cols)+"\n")
        for row in rows:f.write(",".join(str(row.get(c,"")) for c in cols)+"\n")
print(f"wrote {len(rows)} complete cells to {out}")

def ms_cell(row, name):
    return f"{row[name+'_median']/1e6:.2f} [{row[name+'_q1']/1e6:.2f}, {row[name+'_q3']/1e6:.2f}]"

def make_table(title, chosen):
    lines=[f"## {title}","","Median milliseconds [p25, p75]; sizes are encoded bytes.","",
           "| n | t | r | Prove | Cert verify | Full verify | Certificate raw/encoded B | Signature raw/encoded B | Round-1 request B |",
           "|---:|---:|---:|---:|---:|---:|---:|---:|---:|"]
    for row in sorted(chosen,key=lambda x:(x["n"],x["r"])):
        lines.append(f"| {row['n']} | {row['t']} | {row['r']} | {ms_cell(row,'prove_ns')} | {ms_cell(row,'certificate_verify_ns')} | {ms_cell(row,'full_verify_ns')} | {row['analytic_certificate_bytes']}/{row['certificate_bytes_median']:.0f} | {row['analytic_signature_bytes']}/{row['signature_bytes_median']:.0f} | {row['round1_request_bytes_median']:.0f} |")
    return "\n".join(lines)

if rows:
    max_r={}
    for row in rows:max_r[row["n"]]=max(max_r.get(row["n"],-1),row["r"])
    a=[x for x in rows if x["r"]==max_r[x["n"]]]
    b=[x for x in rows if x["n"]==2048]
    expected_a={(n, k) for n, k in ((64,7),(256,9),(1024,11),(2048,12),(4096,13))}
    expected_b={(2048,r) for r in (0,9,12)}
    present_a={(row["n"],row["r"]) for row in a}
    present_b={(row["n"],row["r"]) for row in b}
    complete_a=expected_a <= present_a
    complete_b=expected_b <= present_b
    with open("docs/benchmarks/asiaccs27-20261116/tables.md","w") as f:
        complete=complete_a and complete_b
        f.write("# ASIACCS27 measured tables\n\n" if complete else
                "# ASIACCS27 provisional measured tables\n\n")
        if not complete:
            f.write(f"Incomplete cells: Table A missing {sorted(expected_a-present_a)}; "
                    f"Table B missing {sorted(expected_b-present_b)}. Do not cite as the complete matrix.\n\n")
        f.write(make_table("Table A: Full folding" if complete_a else "Table A: Full folding (partial)",a)+"\n\n")
        f.write(make_table("Table B: r sweep at n=2048",b)+"\n\n")
        lines=["## Signer mode comparison","","Median milliseconds [p25, p75]; request/response sizes are encoded bytes.","",
               "| n | r | Mode | Cert verify | Mask linkage | Round 1 total | Round 2 | Round-1 request B | Round-1 response B |",
               "|---:|---:|---|---:|---:|---:|---:|---:|---:|"]
        for row in sorted(rows,key=lambda x:(x["n"],x["r"])):
            for mode,cert,link,r1,r2,req,resp in (
                ("certificate-only","signer_cert_verify_ns",None,"signer_round1_ns","signer_round2_ns","round1_request_bytes","round1_response_bytes"),
                ("mask-disclosure","mode1_cert_verify_ns","mode1_linkage_ns","mode1_signer_round1_ns","mode1_signer_round2_ns","mode1_round1_request_bytes","mode1_round1_response_bytes")):
                linkage="N/A" if link is None else ms_cell(row,link)
                lines.append(f"| {row['n']} | {row['r']} | {mode} | {ms_cell(row,cert)} | {linkage} | {ms_cell(row,r1)} | {ms_cell(row,r2)} | {row[req+'_median']:.0f} | {row[resp+'_median']:.0f} |")
        f.write("\n".join(lines)+"\n")

registration_files=glob.glob("docs/benchmarks/asiaccs27-20261116/registration-*.jsonl")
registration_rows=[]
for path in registration_files:
    data=[json.loads(line) for line in open(path) if line.strip()]
    if len(data)<100:
        print(f"skip incomplete registration run: {path} ({len(data)}/100)",file=sys.stderr);continue
    for field in ("registration_ns","pop_verify_ns","registration_bytes"):
        vals=[d[field] for d in data]
        registration_rows.append((path,field,len(vals),statistics.median(vals),quantile(vals,.25),quantile(vals,.75),quantile(vals,.95)))
if registration_rows:
    path="docs/benchmarks/asiaccs27-20261116/registration-summary.csv"
    with open(path,"w") as f:
        f.write("source,metric,samples,median,p25,p75,p95\n")
        for row in registration_rows:f.write(",".join(map(str,row))+"\n")
    print(f"wrote registration summary to {path}")

baseline_rows=[]
for path in glob.glob("docs/benchmarks/asiaccs27-20261116/release-plain-schnorr*.jsonl"):
    data=[json.loads(line) for line in open(path) if line.strip()]
    if len(data)<100:
        print(f"skip incomplete baseline run: {path} ({len(data)}/100)",file=sys.stderr);continue
    for field in ("sign_ns","verify_ns","signature_payload_bytes"):
        vals=[d[field] for d in data]
        baseline_rows.append((path,field,len(vals),statistics.median(vals),quantile(vals,.25),
                              quantile(vals,.75),quantile(vals,.95)))
if baseline_rows:
    path="docs/benchmarks/asiaccs27-20261116/baseline-summary.csv"
    with open(path,"w") as f:
        f.write("source,metric,samples,median,p25,p75,p95\n")
        for row in baseline_rows:f.write(",".join(map(str,row))+"\n")
    print(f"wrote baseline summary to {path}")

# Same-library RFC 9591 FROST samples. Composite timings are summed per sample
# before quantiles are computed, matching the rule used for HTA stage totals.
frost_files=glob.glob("docs/benchmarks/asiaccs27-20261116/release-frost-n*.jsonl")
frost_metrics=("round1_total_ns","binding_factors_ns","group_commitment_ns",
               "round2_total_ns","share_verify_ns","aggregate_ns","verify_ns",
               "signature_bytes","public_group_info_bytes")
frost_rows=[]
for path in frost_files:
    data=[json.loads(line) for line in open(path) if line.strip()]
    if len(data)<100:
        print(f"skip incomplete FROST run: {path} ({len(data)}/100)",file=sys.stderr);continue
    n=data[0]["n"]; t=data[0]["t"]
    if any(d["n"]!=n or d["t"]!=t for d in data):raise ValueError(f"mixed FROST parameters: {path}")
    composites={
        "signing_path_ns":[d["round1_total_ns"]+d["binding_factors_ns"]+
                           d["group_commitment_ns"]+d["round2_total_ns"]+
                           d["aggregate_ns"] for d in data],
        "signing_with_share_checks_ns":[d["round1_total_ns"]+d["binding_factors_ns"]+
                           d["group_commitment_ns"]+d["round2_total_ns"]+
                           d["aggregate_ns"]+d["share_verify_ns"] for d in data],
        "signing_with_share_checks_and_verify_ns":[d["round1_total_ns"]+
                           d["binding_factors_ns"]+d["group_commitment_ns"]+
                           d["round2_total_ns"]+d["aggregate_ns"]+
                           d["share_verify_ns"]+d["verify_ns"] for d in data],
    }
    metrics={key:[d[key] for d in data] for key in frost_metrics}
    metrics.update(composites)
    for metric,vals in metrics.items():
        frost_rows.append((path,n,t,metric,len(vals),statistics.median(vals),
                           quantile(vals,.25),quantile(vals,.75),quantile(vals,.95)))
if frost_rows:
    path="docs/benchmarks/asiaccs27-20261116/frost-summary.csv"
    with open(path,"w") as f:
        f.write("source,n,t,metric,samples,median,p25,p75,p95\n")
        for row in frost_rows:f.write(",".join(map(str,row))+"\n")
    print(f"wrote FROST summary to {path}")

# Focused setup/aggregation/verification comparison. HTA setup is measured
# per registered key; FROST setup is one trusted-dealer run for the full group.
comparison_rows=[]
registration_data=[json.loads(line) for path in registration_files
                  for line in open(path) if line.strip()]
hta_setup=[d["registration_ns"]+d["pop_verify_ns"] for d in registration_data]
hta_cells={}
for path in glob.glob("docs/benchmarks/asiaccs27-20261116/release-n*-r*.jsonl"):
    data=[json.loads(line) for line in open(path) if line.strip()]
    if len(data)<100 or not data or "r" not in data[0]:continue
    n=data[0]["n"]
    if n not in hta_cells or data[0]["r"]>hta_cells[n][0]:
        hta_cells[n]=(data[0]["r"],data,path)

def append_comparison(source,n,t,scheme,aggregation,setup,verification,total,basis):
    for metric,vals in (("aggregation",aggregation),("setup",setup),
                        ("verification",verification),("total",total)):
        comparison_rows.append((source,n,t,scheme,metric,len(vals),statistics.median(vals),
                                quantile(vals,.25),quantile(vals,.75),basis))

for n,(r,data,source) in sorted(hta_cells.items()):
    t=data[0]["t"]
    aggregation=[d["nonce_aggregation_ns"]+d["response_aggregation_ns"] for d in data]
    verification=[d["certificate_verify_ns"]+d["share_verification_ns"]+
                  d["full_verify_ns"] for d in data]
    setup=[hta_setup[i%len(hta_setup)] for i in range(len(data))]
    total=[aggregation[i]+verification[i]+setup[i] for i in range(len(data))]
    append_comparison(source,n,t,"ASIACCS27",aggregation,setup,verification,total,
                      "PoP create+verify per key")

for path in frost_files:
    data=[json.loads(line) for line in open(path) if line.strip()]
    if len(data)<100:continue
    n=data[0]["n"];t=data[0]["t"]
    aggregation=[d["binding_factors_ns"]+d["group_commitment_ns"]+d["aggregate_ns"]
                 for d in data]
    verification=[d["share_verify_ns"]+d["verify_ns"] for d in data]
    setup=[data[0]["dealer_setup_ns"]]
    total=[aggregation[i]+verification[i]+setup[0] for i in range(len(data))]
    append_comparison(path,n,t,"FROST",aggregation,setup,verification,total,
                      "trusted dealer setup for full n-party group")

if comparison_rows:
    path="docs/benchmarks/asiaccs27-20261116/aggregation-setup-verification.csv"
    with open(path,"w") as f:
        f.write("source,n,t,scheme,metric,samples,median_ns,p25_ns,p75_ns,setup_basis\n")
        for row in comparison_rows:f.write(",".join(map(str,row))+"\n")
    print(f"wrote stage comparison to {path}")
