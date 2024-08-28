extern crate litcrypt;

use std::io::{Error, Result};
use trainer_base::{
    memory::Process,
    misc::pause,
    process::{get_pid_by_name, get_process_base, get_process_info},
};

litcrypt::use_litcrypt!();

fn get_pointer_address(
    base_address: usize,
    offsets: Vec<usize>,
    process: &Process,
) -> Result<usize> {
    let mut result_address = base_address;
    for (index, offset) in offsets.iter().enumerate() {
        let mut buffer: [u8; 4] = [0; 4];

        process
            .read_memory(result_address + offset, &mut buffer)
            .map_err(|e| {
                Error::new(
                    std::io::ErrorKind::Other,
                    format!(
                        "[get_pointer_address]: Failed to read memory: {} {}",
                        e, offset
                    ),
                )
            })?;

        result_address = u32::from_le_bytes(buffer) as usize;
        println!("[get_pointer_address]: {} -> {:#x}", index, result_address);
    }

    Ok(result_address)
}

fn main() {
    let localplayer_ptr_offset = 0x0018B0B8;
    let localplayer_offset = 0x404;
    let health_offset = 0x04;

    let b_process_name = litcrypt::lc!("ac_client.exe");
    let process_name = &b_process_name;

    let pid = match get_pid_by_name(process_name) {
        Some(pid) => pid,
        None => {
            println!("Process not found: {}", process_name);
            return pause();
        }
    };

    println!("Found PID: {}", pid);

    match get_process_info(pid) {
        Some(info) => {
            println!("Process Name: {}", info.name);
            println!("Memory Usage: {} bytes", info.memory_usage);
            println!("Handle Count: {}", info.handle_count);
            println!("Thread Count: {}", info.thread_count);
        }
        None => {
            println!("Failed to retrieve information for PID {}", pid);
        }
    }

    let process = Process::new(pid);
    let base_address = match get_process_base(pid, process_name) {
        Some(base_address) => base_address as usize,
        None => {
            println!("Module not found");
            return pause();
        }
    };

    println!(
        "Base address of module {}: {:#x}",
        process_name, base_address
    );

    let localplayer_ptr_address =
        match get_pointer_address(base_address, vec![localplayer_ptr_offset, 0x0], &process) {
            Ok(address) => address,
            Err(e) => {
                println!("{}", e);
                return pause();
            }
        };

    let localplayer_address = localplayer_ptr_address + localplayer_offset;
    println!("LocalPlayer Address {:#x}", localplayer_address);

    let health_value_address = localplayer_address + health_offset;
    println!("Health Value Address {:#x}", health_value_address);

    match process.write_memory(health_value_address, &999) {
        Ok(_) => println!("Successfully wrote value at {:#x}", health_value_address),
        Err(e) => {
            eprintln!(
                "Failed to write memory at {:#x}: {}",
                health_value_address, e
            );
        }
    };

    pause();
}
