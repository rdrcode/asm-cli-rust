#[macro_export]
macro_rules! emu_start {
    ($emu:ident, $s_addr:expr, $e_addr:expr, $dur:expr, $num:expr) => {
        $emu.emu_start($s_addr, $e_addr, $dur, $num)
            .map_err(|err| anyhow::Error::new(ExecutionError::UnicornError)
                .context(format!("Failure to start emulator at 0x{:08x}: {:?}", $s_addr, err))
            );
    };
}

#[macro_export]
macro_rules! mem_map {
    ($emu:ident, $addr:expr, $size:expr, $perm:expr) => {
        $emu.mem_map($addr, $size, $perm)
            .map_err(|err| anyhow::Error::new(ExecutionError::UnicornError)
                .context(format!("Failure to map memory at 0x{:08x}: {:?}", $addr, err))
            );
    };
}

#[macro_export]
macro_rules! mem_unmap {
    ($emu:ident, $addr:expr, $size:expr) => {
        $emu.mem_unmap($addr, $size)
            .map_err(|err| anyhow::Error::new(ExecutionError::UnicornError)
                .context(format!("Failure to unmap memory at 0x{:08x}: {:?}", $addr, err))
            );
    };
}

#[macro_export]
macro_rules! mem_regions {
    ($emu:ident) => {
        $emu.mem_regions()
            .map_err(|err| anyhow::Error::new(ExecutionError::UnicornError)
                .context(format!("Failure to list memory regions: {:?}", err))
            );
    };
}

#[macro_export]
macro_rules! mem_write {
    ($emu:ident, $addr:expr, $bytes:expr) => {
        $emu.mem_write($addr, $bytes)
            .map_err(|err| anyhow::Error::new(ExecutionError::UnicornError)
                .context(format!("Failure to write to memory at 0x{:08x}: {:?}", $addr, err))
            );
    };
}

#[macro_export]
macro_rules! mem_read_as_vec {
    ($emu:ident, $addr:expr, $size:expr) => {
        $emu.mem_read_as_vec($addr, $size)
            .map_err(|err| anyhow::Error::new(ExecutionError::UnicornError)
                .context(format!("Failure to read vec from memory at 0x{:08x}: {:?}", $addr, err))
            );
    };
}    

#[macro_export]
macro_rules! reg_write {
    ($emu:ident, $reg:expr, $val:expr) => {
        $emu.reg_write($reg, $val)
            .map_err(|err| anyhow::Error::new(ExecutionError::UnicornError)
                .context(format!("Failure to write to register {}: {:?}", $reg, err))
            );
    };
}    

#[macro_export]
macro_rules! reg_read {
    ($emu:ident, $reg:expr) => {
        $emu.reg_read($reg)
            .map_err(|err| anyhow::Error::new(ExecutionError::UnicornError)
                .context(format!("Failure to read from register {}: {:?}", $reg, err))
            );
    };
}    

#[macro_export]
macro_rules! ok_or_error {
    ($result:expr) => {
        match $result {
            Ok(result) => result,
            Err(err)   => eprintln!("{}: '{:?}'", Red.paint("ERROR"), err),
        };
    };
}