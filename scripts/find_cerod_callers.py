#!/usr/bin/env python3
import re,subprocess,sys,os,json
BIN='KeyKey-Executable-Darwin-x86_64.exe'
OTV=subprocess.check_output(['otool','-l',BIN]).decode()
# parse sections and find __cstring section robustly
section_addr=None; section_offset=None; section_size=None
blocks=OTV.split('\nSection\n')
for b in blocks:
    if 'sectname __cstring' in b:
        m_addr=re.search(r"addr\s+0x([0-9a-fA-F]+)", b)
        m_off=re.search(r"offset\s+(\d+)", b)
        m_size=re.search(r"size\s+0x([0-9a-fA-F]+)", b)
        if m_addr and m_off and m_size:
            section_addr=int(m_addr.group(1),16)
            section_offset=int(m_off.group(1))
            section_size=int(m_size.group(1),16)
            break
if section_addr is None:
    print('cannot find __cstring section via otool -l', file=sys.stderr); sys.exit(1)
print(f'__cstring vmaddr=0x{section_addr:x} fileoff={section_offset} size=0x{section_size:x}')
# read cstring bytes
with open(BIN,'rb') as f:
    f.seek(section_offset)
    cbytes=f.read(section_size)
# map vmaddr->string
cstring_map={}
i=0
while i<len(cbytes):
    if cbytes[i]==0:
        i+=1; continue
    j=i
    while j<len(cbytes) and cbytes[j]!=0:
        j+=1
    s=cbytes[i:j].decode(errors='replace')
    addr=section_addr + i
    cstring_map[addr]=s
    i=j+1
# parse disasm
otv2=subprocess.check_output(['otool','-tv',BIN]).decode().splitlines()
lines=[]
for l in otv2:
    m=re.match(r"^([0-9a-fA-Fx]+)\s+(.*)$",l)
    if m:
        addr=int(m.group(1),16)
        instr=m.group(2)
        lines.append((addr,instr))
# helper: find index of address
addr_to_index={addr:i for i,(addr,_) in enumerate(lines)}
targets=[0x100160018,0x1000759b0,0x10006c4a0]
results=[]
for t in targets:
    found_ct=0
    for i,(addr,instr) in enumerate(lines):
        if re.search(rf"callq\s+0x{t:x}\b", instr):
            found_ct+=1
            start=max(0,i-24)
            window=lines[start:i]
            found=[]
            leaqs=[]
            for wa,winstr in window:
                # LEAQ RIP-relative
                m=re.search(r"leaq\s+0x([0-9a-fA-F]+)\(%rip\),\s+%r([a-z]+)", winstr)
                if m:
                    imm=int(m.group(1),16)
                    idx=addr_to_index.get(wa)
                    next_addr=lines[idx+1][0] if idx is not None and idx+1<len(lines) else wa+6
                    targ=next_addr+imm
                    s=cstring_map.get(targ)
                    leaqs.append({'instr_addr':hex(wa),'instr':winstr.strip(),'rip_target':hex(targ),'resolved_string':s})
                m2=re.search(r"leaq\s+(-?0x[0-9a-fA-F]+)\(%rbp\),\s+%r([a-z]+)", winstr)
                if m2:
                    leaqs.append({'instr_addr':hex(wa),'instr':winstr.strip(),'stack_buffer':m2.group(1)})
                m3=re.search(r"movq\s+\$0x([0-9a-fA-F]+),\s+%r([a-z]+)", winstr)
                if m3:
                    imm=int(m3.group(1),16)
                    s=cstring_map.get(imm)
                    leaqs.append({'instr_addr':hex(wa),'instr':winstr.strip(),'imm_addr':hex(imm),'resolved_string':s})
            # also look for direct uses of known strings in the window
            keywords=[]
            for addr_s,s in cstring_map.items():
                if 'cerod' in s or 'KeyKey.db' in s or '7bb07b8d471d642e' in s:
                    keywords.append((addr_s,s))
            keyword_hits=[]
            for kw_addr,kw_s in keywords:
                for la in leaqs:
                    if 'rip_target' in la and int(la['rip_target'],16)==kw_addr:
                        keyword_hits.append({'kw_addr':hex(kw_addr),'kw_s':kw_s,'instr':la})
            results.append({'call_site':hex(addr),'target':hex(t),'context':[(hex(a),i.strip()) for a,i in window[-12:]], 'leaqs':leaqs, 'keyword_hits':keyword_hits})
    print(f'target 0x{t:x} found {found_ct} call sites')

# produce human readable summary
out_lines=[]
for r in results:
    cs=r['call_site']
    tgt=r['target']
    out_lines.append(f'CALL {cs} -> target {tgt}\n')
    # context (last few instructions before call)
    for a,ins in r['context']:
        out_lines.append(f"   {a}: {ins}\n")
    if r['leaqs']:
        out_lines.append('  detected LEAQs:\n')
        for f in r['leaqs']:
            s=f.get('resolved_string')
            if s:
                out_lines.append(f"    {f['instr_addr']}: {f['instr']} -> '{s}'\n")
            elif 'stack_buffer' in f:
                out_lines.append(f"    {f['instr_addr']}: {f['instr']} -> stack {f['stack_buffer']}\n")
            elif 'imm_addr' in f:
                out_lines.append(f"    {f['instr_addr']}: {f['instr']} -> imm {f['imm_addr']} (string={f.get('resolved_string')})\n")
            else:
                out_lines.append(f"    {f['instr_addr']}: {f['instr']} -> target {f.get('rip_target')}\n")
    if r['keyword_hits']:
        out_lines.append('  keyword hits:\n')
        for kh in r['keyword_hits']:
            out_lines.append(f"    {kh['kw_s']} at {kh['kw_addr']} via {kh['instr']}\n")
    out_lines.append('\n')
# write outputs
os.makedirs('outputs',exist_ok=True)
with open('outputs/cerod_callers.json','w') as f:
    json.dump(results,f,indent=2)
with open('outputs/cerod_callers.txt','w') as f:
    f.writelines(out_lines)
print('wrote outputs/cerod_callers.txt and json')
print('sample lines:')
print(''.join(out_lines[:80]))
