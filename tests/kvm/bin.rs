#![feature(linkage, naked_functions, asm)]
// In this example we will construct a single CPU x86 VM which will execute
// "inb 0x01" at ring 0

extern crate kvm;
extern crate memmap;
extern crate x86;

use kvm::{Capability, Exit, IoDirection, System, Vcpu, VirtualMachine};
use memmap::{Mmap, Protection};
use std::fs::File;
use std::io::{BufRead, BufReader};
use x86::current::paging::*;
use x86::shared::paging::*;

#[naked]
unsafe extern "C" fn use_the_port() {
    asm!("inb $0, %al" :: "i"(0x01) :: "volatile");
}

#[test]
fn io_example() {
    let vaddr = VAddr::from_usize(&use_the_port as *const _ as _);
    println!("{} {}", pml4_index(vaddr), pdpt_index(vaddr));
    // set up a page table that identity maps the lower half of the address space
    let mut anon_mmap = Mmap::anonymous(2 * (1 << 20), Protection::ReadWrite).unwrap();
    let slice = unsafe { anon_mmap.as_mut_slice() };
    let pml4: &mut PML4 = unsafe { ::std::mem::transmute(&mut slice[0x1000]) };
    for i in 0..256 {
        let offset = 0x2000 + 0x1000 * i;
        pml4[i] = PML4Entry::new(PAddr::from_u64(offset as _), PML4_P | PML4_RW);
        let pdpt: &mut PDPT = unsafe { ::std::mem::transmute(&mut slice[offset]) };
        for j in 0..512 {
            pdpt[j] = PDPTEntry::new(PAddr::from_u64(((512 * i + j) as u64) << 30),
                                     PDPT_P | PDPT_RW | PDPT_PS);
            if i == pml4_index(vaddr) && j == pdpt_index(vaddr) {
                println!("{:?}", pml4[i].get_address());
                println!("{:?}", pdpt[j].get_address());
            }
        }
    }

    slice[0x1f0000] = 0xe4;
    slice[0x1f0001] = 0x01;

    // Initialize the KVM system
    let sys = System::initialize().unwrap();

    // Create a Virtual Machine
    let mut vm = VirtualMachine::create(&sys).unwrap();

    // Ensure that the VM supports memory backing with user memory
    assert!(vm.check_capability(Capability::UserMemory) > 0);

    vm.set_user_memory_region(0, slice, 0).unwrap();

    let f = File::open("/proc/self/maps").unwrap();
    let reader = BufReader::new(f);

    for line in reader.lines() {
        let line = line.unwrap();
        //println!("{}", line);
        let mut s = line.split(' ');
        let mut s2 = s.next().unwrap().split('-');
        let begin = usize::from_str_radix(s2.next().unwrap(), 16).unwrap();
        let end = usize::from_str_radix(s2.next().unwrap(), 16).unwrap();
        if end < 0x800000000000 {
            let perm = s.next().unwrap();
            //println!("{:#X}-{:#X} {}", begin, end, perm);
            let slice = {
                let begin_ptr: *mut u8 = begin as *const u8 as _;
                unsafe { ::std::slice::from_raw_parts_mut(begin_ptr, end - begin) }
            };
            vm.set_user_memory_region(begin as _, slice, 0).unwrap();
        }
    }

    // Create a new VCPU
    let mut vcpu = Vcpu::create(&mut vm).unwrap();

    // Set supported CPUID (KVM fails without doing this)
    let mut cpuid = sys.get_supported_cpuid().unwrap();
    vcpu.set_cpuid2(&mut cpuid).unwrap();

    // Setup the special registers
    let mut sregs = vcpu.get_sregs().unwrap();

    // Set the code segment to have base 0, limit 4GB (flat segmentation)
    sregs.cs.base = 0x0;
    sregs.cs.limit = 0xffffffff;
    sregs.cs.selector = 0x8;
    sregs.cs._type = 0xb;
    sregs.cs.present = 1;
    sregs.cs.dpl = 0;
    sregs.cs.db = 0;
    sregs.cs.s = 1;
    sregs.cs.l = 1;
    sregs.cs.g = 1;
    sregs.cs.avl = 0;

    sregs.ss.base = 0x0;
    sregs.ss.limit = 0xffffffff;
    sregs.ss.selector = 0;
    sregs.ss._type = 0;
    sregs.ss.present = 0;
    sregs.ss.dpl = 0;
    sregs.ss.db = 1;
    sregs.ss.s = 0;
    sregs.ss.l = 0;
    sregs.ss.g = 1;
    sregs.ss.avl = 0;

    sregs.ds.base = 0x0;
    sregs.ds.limit = 0xffffffff;
    sregs.ds.selector = 0;
    sregs.ds._type = 0;
    sregs.ds.present = 0;
    sregs.ds.dpl = 0;
    sregs.ds.db = 1;
    sregs.ds.s = 0;
    sregs.ds.l = 0;
    sregs.ds.g = 1;
    sregs.ds.avl = 0;

    sregs.es.base = 0x0;
    sregs.es.limit = 0xffffffff;
    sregs.es.selector = 0;
    sregs.es._type = 0;
    sregs.es.present = 0;
    sregs.es.dpl = 0;
    sregs.es.db = 1;
    sregs.es.s = 0;
    sregs.es.l = 0;
    sregs.es.g = 1;
    sregs.es.avl = 0;

    sregs.fs.base = 0x0;
    sregs.fs.base = 0x0;
    sregs.fs.limit = 0xffffffff;
    sregs.fs.selector = 0;
    sregs.fs._type = 0;
    sregs.fs.present = 0;
    sregs.fs.dpl = 0;
    sregs.fs.db = 1;
    sregs.fs.s = 0;
    sregs.fs.l = 0;
    sregs.fs.g = 1;
    sregs.fs.avl = 0;

    sregs.gs.base = 0x0;
    sregs.gs.limit = 0xffffffff;
    sregs.gs.selector = 0;
    sregs.gs._type = 0;
    sregs.gs.present = 0;
    sregs.gs.dpl = 0;
    sregs.gs.db = 1;
    sregs.gs.s = 0;
    sregs.gs.l = 0;
    sregs.gs.g = 1;
    sregs.gs.avl = 0;

    // We don't need to populate the GDT if we have our segments setup
    // cr0 - protected mode on, paging enabled
    sregs.cr0 = 0x80050033;
    sregs.cr3 = 0x1000;
    sregs.cr4 = 0x1406b0;
    sregs.efer = 0xd01;

    // Set the special registers
    vcpu.set_sregs(&sregs).unwrap();

    let mut regs = vcpu.get_regs().unwrap();
    // set the instruction pointer to 1 MB
    //regs.rip = &use_the_port as *const _ as _;
    regs.rip = 0x1f0000;
    println!("regs.rip = {:X}", regs.rip);
    // regs.rflags = 0x2;
    regs.rflags = 0x246;
    vcpu.set_regs(&regs).unwrap();

    // Actually run the VCPU
    let run = unsafe { vcpu.run() }.unwrap();

    // Ensure that the exit reason we get back indicates that the I/O
    // instruction was executed
    assert!(run.exit_reason == Exit::Io);
    let io = unsafe { *run.io() };
    assert!(io.direction == IoDirection::In);
    assert!(io.size == 1);
    assert!(io.port == 0x1);
    unsafe {
        println!("{:#?}", *run.io());
    }
}
