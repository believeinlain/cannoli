//! An example user of Cannoli which symbolizes a trace

use cannoli::{create_cannoli, Cannoli};
use memfd_exec::MemFdExecutable;
use qemu::qemu_x86_64;
use std::{process::exit, sync::Arc, thread};

/// An original pointer address, and then a resolved symbol + offset for that
/// address
struct SymOff {
    /// The "raw", original address
    addr: u64,

    /// Symbol
    symbol: &'static str,

    /// Offset from the base of the symbol
    offset: u64,
}

impl std::fmt::Display for SymOff {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        if self.offset != 0 {
            write!(
                f,
                "{:#018x} ({}+{:#x})",
                self.addr, self.symbol, self.offset
            )
        } else {
            write!(f, "{:#018x} ({})", self.addr, self.symbol)
        }
    }
}

enum Operation {
    Exec {
        pc: SymOff,
    },
    Read {
        pc: SymOff,
        addr: SymOff,
        val: u64,
        sz: u8,
    },
    Write {
        pc: SymOff,
        addr: SymOff,
        val: u64,
        sz: u8,
    },
}

/// The structure we implement [`Cannoli`] for!
struct Tracer;

/// Context shared between threads
struct Context {
    /// Lookup from an address to a symbol, stored in sorted order
    symbols: Vec<(u64, &'static str)>,
}

impl Context {
    /// Attempt to resolve a symbol into a symbol and an offset
    fn resolve(&self, addr: u64) -> SymOff {
        // eprintln!("Resolving 0x{addr:x}");
        // Get access to the symbols
        let symbols = &self.symbols;

        // Find the symbol
        match symbols.binary_search_by_key(&addr, |x| x.0) {
            Ok(pos) => {
                // Direct symbol match
                SymOff {
                    addr,
                    symbol: symbols[pos].1,
                    offset: 0,
                }
            }
            Err(pos) => {
                // Found location after symbol, find the nearest symbol below
                if let Some((sa, sym)) = pos.checked_sub(1).and_then(|x| symbols.get(x)) {
                    // Got symbol below
                    SymOff {
                        addr,
                        symbol: sym,
                        offset: addr - sa,
                    }
                } else {
                    // No symbols below this address, just emit the PC
                    SymOff {
                        addr,
                        symbol: "<unknown>",
                        offset: addr,
                    }
                }
            }
        }
    }
}

impl Cannoli for Tracer {
    /// The type emit in the serialized trace
    type Trace = Operation;

    /// Context, the shared, immutable context shared between all threads doing
    /// processing. We stuff our symbol table here.
    type TidContext = Context;

    type PidContext = ();

    fn init_pid(_info: &cannoli::ClientInfo) -> Arc<Self::PidContext> {
        Arc::new(())
    }

    /// Load the symbol table
    fn init_tid(_pid: &Self::PidContext, _info: &cannoli::ClientInfo) -> (Self, Self::TidContext) {
        // Symbols
        let mut symbols = Vec::new();

        // Load the symbol file up and leak it so all the lifetimes are static
        let data = std::fs::read_to_string("symbols.txt").unwrap();
        let data = Box::leak(data.into_boxed_str());

        // Parse each line into an address and symbol
        for line in data.lines() {
            let chunk = line.splitn(3, ' ').collect::<Vec<_>>();

            if let Ok(addr) = u64::from_str_radix(chunk[0], 16) {
                let sym = chunk[2];
                symbols.push((addr, sym));
            }
        }

        // Sort the symbols by address
        symbols.sort_by_key(|x| x.0);

        (Self, Context { symbols })
    }

    fn mmap(
        _pid: &Self::PidContext,
        _tid: &Self::TidContext,
        base: u64,
        _len: u64,
        _anon: bool,
        _read: bool,
        _write: bool,
        exec: bool,
        path: &str,
        offset: u64,
        _trace: &mut Vec<Self::Trace>,
    ) {
        if path.len() > 0 {
            eprintln!("mmap: path={path} base=0x{base:x} offset=0x{offset:x} exec={exec}");
        }
    }

    /// Convert PCs into symbol + offset in parallel
    fn exec(
        _pid: &Self::PidContext,
        tid: &Self::TidContext,
        pc: u64,
        trace: &mut Vec<Self::Trace>,
    ) {
        trace.push(Operation::Exec {
            pc: tid.resolve(pc),
        });
    }

    /// Symbolize reads
    fn read(
        _pid: &Self::PidContext,
        tid: &Self::TidContext,
        pc: u64,
        addr: u64,
        val: u64,
        sz: u8,
        trace: &mut Vec<Self::Trace>,
    ) {
        trace.push(Operation::Read {
            pc: tid.resolve(pc),
            addr: tid.resolve(addr),
            val,
            sz,
        });
    }

    /// Symbolize writes
    fn write(
        _pid: &Self::PidContext,
        tid: &Self::TidContext,
        pc: u64,
        addr: u64,
        val: u64,
        sz: u8,
        trace: &mut Vec<Self::Trace>,
    ) {
        trace.push(Operation::Write {
            pc: tid.resolve(pc),
            addr: tid.resolve(addr),
            val,
            sz,
        });
    }

    /// Print the trace we processed!
    fn trace(&mut self, _pid: &Self::PidContext, _tid: &Self::TidContext, trace: &[Self::Trace]) {
        for op in trace {
            match op {
                Operation::Exec { pc } => {
                    println!("\x1b[0;34mEXEC\x1b[0m   @ {pc}");
                }
                Operation::Read { pc, addr, val, sz } => {
                    println!(
                        "\x1b[0;32mREAD{sz}\x1b[0m  @ {pc} | \
                        {addr} ={val:#x}"
                    );
                }
                Operation::Write { pc, addr, val, sz } => {
                    println!(
                        "\x1b[0;31mWRITE{sz}\x1b[0m @ {pc} | \
                        {addr} ={val:#x}"
                    );
                }
            }
        }
    }
}

fn main() {
    let tracer = thread::spawn(|| create_cannoli::<Tracer>(2).unwrap());
    let mut qemu_proc = MemFdExecutable::new("qemu-x86_64", qemu_x86_64())
        .args([
            "-cannoli",
            "../../target/release/libjitter_always.so",
            "hello-x86_64",
        ])
        .spawn()
        .unwrap();
    qemu_proc.wait().unwrap();
    if tracer.is_finished() {
        tracer.join().unwrap();
    } else {
        exit(0)
    }
}
