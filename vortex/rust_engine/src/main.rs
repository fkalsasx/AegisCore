//! AEGIS-VORTEX :: Modül 1 Yüksek Hızlı Rust Statik, CTPH Fuzzy Hash,
//! Shannon Entropi ve PE IAT İçe Aktarma Tablosu Ayrıştırıcısı (Zero External Crates)

use std::collections::HashSet;
use std::env;
use std::fs;
use std::path::Path;
use std::thread;

const B64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

#[derive(Clone, Copy)]
struct SectionCoord {
    vaddr: u32,
    vsize: u32,
    rptr: u32,
    rsize: u32,
}

fn read_u16_le(data: &[u8], off: usize) -> Option<u16> {
    data.get(off..off + 2)
        .map(|s| u16::from_le_bytes([s[0], s[1]]))
}

fn read_u32_le(data: &[u8], off: usize) -> Option<u32> {
    data.get(off..off + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn read_u64_le(data: &[u8], off: usize) -> Option<u64> {
    data.get(off..off + 8)
        .map(|s| u64::from_le_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]]))
}

fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    let mut ent = 0.0;
    for &c in &counts {
        if c > 0 {
            let p = (c as f64) / len;
            ent -= p * p.log2();
        }
    }
    (ent * 10000.0).round() / 10000.0
}

fn compute_ctph_for_block(data: &[u8], block_size: u32) -> (String, String) {
    let mut primary = String::with_capacity(64);
    let mut secondary = String::with_capacity(64);
    let mut win = [0u8; 7];
    let mut win_idx = 0usize;
    let (mut h1, mut h2, mut h3): (u32, u32, u32) = (0, 0, 0);
    let mut fnv_p: u32 = 0x811C9DC5;
    let mut fnv_s: u32 = 0x811C9DC5;

    for &b in data {
        let old = win[win_idx] as u32;
        let bu = b as u32;
        h2 = h2.wrapping_sub(h1).wrapping_add(7u32.wrapping_mul(bu));
        h1 = h1.wrapping_add(bu).wrapping_sub(old);
        h3 = (h3 << 5) ^ bu;
        win[win_idx] = b;
        win_idx = (win_idx + 1) % 7;
        let roll = h1.wrapping_add(h2).wrapping_add(h3);

        fnv_p = fnv_p.wrapping_mul(0x01000193) ^ bu;
        fnv_s = fnv_s.wrapping_mul(0x01000193) ^ bu;

        if roll % block_size == block_size - 1 {
            primary.push(B64[(fnv_p & 63) as usize] as char);
            fnv_p = 0x811C9DC5;
            if primary.len() >= 64 {
                break;
            }
        }
        if roll % (block_size * 2) == (block_size * 2) - 1 {
            secondary.push(B64[(fnv_s & 63) as usize] as char);
            fnv_s = 0x811C9DC5;
        }
    }
    primary.push(B64[(fnv_p & 63) as usize] as char);
    secondary.push(B64[(fnv_s & 63) as usize] as char);
    (primary, secondary)
}

fn compute_ctph_fuzzy_hash(data: &[u8]) -> String {
    if data.is_empty() {
        return "3::".to_string();
    }
    let mut block_size: u32 = 8;
    while (block_size as usize) * 64 < data.len() && block_size < 65536 {
        block_size *= 2;
    }
    let (mut p1, mut p2) = compute_ctph_for_block(data, block_size);
    while p1.len() < 20 && block_size > 4 {
        block_size /= 2;
        let res = compute_ctph_for_block(data, block_size);
        p1 = res.0;
        p2 = res.1;
    }
    format!("{}:{}:{}", block_size, p1, p2)
}

fn rva_to_offset(rva: u32, secs: &[SectionCoord]) -> Option<usize> {
    for s in secs {
        let span = s.vsize.max(s.rsize);
        if rva >= s.vaddr && rva < s.vaddr.saturating_add(span) {
            return Some((s.rptr + (rva - s.vaddr)) as usize);
        }
    }
    None
}

fn read_cstr(data: &[u8], off: usize) -> String {
    if off >= data.len() {
        return String::new();
    }
    let slice = &data[off..data.len().min(off + 256)];
    let end = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
    String::from_utf8_lossy(&slice[..end]).into_owned()
}

fn analyze_pe_and_iat(data: &[u8]) -> (bool, bool, bool, String) {
    if data.len() < 64 || data[0] != b'M' || data[1] != b'Z' {
        return (false, false, false, String::new());
    }
    let pe_off = match read_u32_le(data, 0x3C) {
        Some(v) => v as usize,
        None => return (false, false, false, String::new()),
    };
    if data.get(pe_off..pe_off + 4) != Some(b"PE\0\0") {
        return (false, false, false, String::new());
    }

    let num_secs = read_u16_le(data, pe_off + 6).unwrap_or(0) as usize;
    let opt_size = read_u16_le(data, pe_off + 20).unwrap_or(0) as usize;
    let opt_off = pe_off + 24;
    let magic = read_u16_le(data, opt_off).unwrap_or(0);
    let is_pe64 = magic == 0x20B;

    let dd_off = opt_off + if is_pe64 { 112 } else { 96 };
    let imp_rva = read_u32_le(data, dd_off + 8).unwrap_or(0);
    let imp_size = read_u32_le(data, dd_off + 12).unwrap_or(0);

    let sec_table = opt_off + opt_size;
    let mut secs = Vec::new();
    let mut packed_suspicious = false;
    let mut sec_json = String::from("[");

    for i in 0..num_secs.min(32) {
        let off = sec_table + i * 40;
        if off + 40 > data.len() {
            break;
        }
        let sec_name = read_cstr(data, off);
        let vsize = read_u32_le(data, off + 8).unwrap_or(0);
        let vaddr = read_u32_le(data, off + 12).unwrap_or(0);
        let rsize = read_u32_le(data, off + 16).unwrap_or(0);
        let rptr = read_u32_le(data, off + 20).unwrap_or(0);
        secs.push(SectionCoord { vaddr, vsize, rptr, rsize });

        let end = (rptr as usize).saturating_add(rsize as usize).min(data.len());
        let sec_bytes = if (rptr as usize) < end { &data[rptr as usize..end] } else { &[] };
        let ent = shannon_entropy(sec_bytes);
        if ent > 7.2 {
            packed_suspicious = true;
        }
        if i > 0 {
            sec_json.push(',');
        }
        sec_json.push_str(&format!("{{\"name\":\"{}\",\"entropy\":{}}}", sec_name, ent));
    }
    sec_json.push(']');

    let mut apis = HashSet::new();
    if imp_rva > 0 && imp_size >= 20 {
        if let Some(mut idt_off) = rva_to_offset(imp_rva, &secs) {
            while idt_off + 20 <= data.len() {
                let oft = read_u32_le(data, idt_off).unwrap_or(0);
                let name_rva = read_u32_le(data, idt_off + 12).unwrap_or(0);
                let ft = read_u32_le(data, idt_off + 16).unwrap_or(0);
                if oft == 0 && name_rva == 0 && ft == 0 {
                    break;
                }
                let thunk_rva = if oft != 0 { oft } else { ft };
                if let Some(mut t_off) = rva_to_offset(thunk_rva, &secs) {
                    let step = if is_pe64 { 8 } else { 4 };
                    while t_off + step <= data.len() {
                        let val = if is_pe64 {
                            read_u64_le(data, t_off).unwrap_or(0)
                        } else {
                            read_u32_le(data, t_off).unwrap_or(0) as u64
                        };
                        if val == 0 {
                            break;
                        }
                        let ord_bit = if is_pe64 { 1u64 << 63 } else { 1u64 << 31 };
                        if (val & ord_bit) == 0 {
                            if let Some(hn_off) = rva_to_offset((val & 0x7FFF_FFFF) as u32, &secs) {
                                let api = read_cstr(data, hn_off + 2);
                                if !api.is_empty() {
                                    apis.insert(api.to_lowercase());
                                }
                            }
                        }
                        t_off += step;
                    }
                }
                idt_off += 20;
            }
        }
    }

    let has_alloc = apis.contains("virtualallocex") || apis.contains("ntallocatevirtualmemory");
    let has_write = apis.contains("writeprocessmemory") || apis.contains("ntwritevirtualmemory");
    let has_exec = apis.contains("createremotethread") || apis.contains("queueuserapc") || apis.contains("ntcreatethreadex");
    let inj_flag = has_alloc && has_write && has_exec;

    (true, packed_suspicious, inj_flag, sec_json)
}

fn scan_single(path: &Path) -> String {
    match fs::read(path) {
        Ok(data) => {
            let ent = shannon_entropy(&data);
            let fuzzy = compute_ctph_fuzzy_hash(&data);
            let (is_pe, packed_sec, inj_flag, sec_json) = analyze_pe_and_iat(&data);
            let packed = ent > 7.2 || packed_sec;
            format!(
                "{{\"source_module\":\"MOD1_RUST_STATIC\",\"path\":\"{}\",\"size\":{},\"entropy\":{},\"fuzzy_hash\":\"{}\",\"is_pe\":{},\"packed_suspicious\":{},\"process_injection_flag\":{},\"sections\":{}}}",
                path.display().to_string().replace('\\', "\\\\"),
                data.len(),
                ent,
                fuzzy,
                is_pe,
                packed,
                inj_flag,
                if sec_json.is_empty() { "[]".to_string() } else { sec_json }
            )
        }
        Err(e) => format!("{{\"error\":\"{}\"}}", e),
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        println!("{{\"status\":\"ready\",\"usage\":\"aegis_vortex_rust_scanner <file1> [file2 ...]\"}}");
        return;
    }

    thread::scope(|s| {
        let mut handles = Vec::new();
        for arg in &args[1..] {
            handles.push(s.spawn(move || scan_single(Path::new(arg))));
        }
        for h in handles {
            if let Ok(line) = h.join() {
                println!("{}", line);
            }
        }
    });
}
