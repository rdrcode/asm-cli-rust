use std::fmt;


#[derive(Debug)]
pub struct InterruptX86 {
    pub(crate) id: u32,
}

impl fmt::Display for InterruptX86 {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match self.id {
            0x00 => write!(fmt, "Division by zero"),
            0x01 => write!(fmt, "Single-step interrupt"),
            0x02 => write!(fmt, "NMI"),
            0x03 => write!(fmt, "Breakpoint"),
            0x04 => write!(fmt, "Overflow"),
            0x05 => write!(fmt, "Bound Range Exceeded"),
            0x06 => write!(fmt, "Invalid Opcode"),
            0x07 => write!(fmt, "Coprocessor not available"),
            0x08 => write!(fmt, "Double Fault"),
            0x09 => write!(fmt, "Coprocessor Segment Overrun"),
            0x0a => write!(fmt, "Invalid Task State Segment"),
            0x0b => write!(fmt, "Segment not present"),
            0x0c => write!(fmt, "Stack Segment Fault"),
            0x0d => write!(fmt, "General Protection Fault"),
            0x0e => write!(fmt, "Page Fault"),
            0x0f => write!(fmt, "Reserved"),
            0x10 => write!(fmt, "x87 Floating Point Exception"),
            0x11 => write!(fmt, "Alignment Check"),
            0x12 => write!(fmt, "Machine Check"),
            0x13 => write!(fmt, "SIMD Floating-Point Exception"),
            0x14 => write!(fmt, "Virtualization Exception"),
            0x15 => write!(fmt, "Control Protection Exception"),
            0x80 => write!(fmt, "Linux System Call"),
            _    => write!(fmt, "Undefined Interrupt"),
        }
    }
}
