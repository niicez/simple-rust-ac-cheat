extern crate winapi;

use std::ffi::{CStr, CString};
use std::mem::size_of;
use std::mem::size_of_val;
use std::ptr::null_mut;

use winapi::shared::minwindef::{DWORD, FALSE, HMODULE, MAX_PATH};
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use winapi::um::processthreadsapi::{GetProcessHandleCount, OpenProcess};
use winapi::um::psapi::{
    EnumProcesses, GetModuleFileNameExW, GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS,
};
use winapi::um::tlhelp32::{
    CreateToolhelp32Snapshot, Module32First, Module32Next, Process32First, Process32Next,
    Thread32First, Thread32Next, MODULEENTRY32, PROCESSENTRY32, TH32CS_SNAPMODULE,
    TH32CS_SNAPMODULE32, TH32CS_SNAPPROCESS, TH32CS_SNAPTHREAD, THREADENTRY32,
};
use winapi::um::winnt::{PROCESS_ALL_ACCESS, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};

/* Example usage:
let b_process_name: &str ="s2_mp64_ship.exe";
let pid = match get_pid_by_name(process_name) {
    Some(pid) => pid,
    None => {
        println!("Process not found");
        pause();
        return;
    }
};
println!("Found PID: {}", pid);
 */
pub fn get_pid_by_name(process_name: &str) -> Option<u32> {
    unsafe {
        let mut process_ids: [DWORD; 1024] = [0; 1024];
        let mut bytes_needed: DWORD = 0;

        if EnumProcesses(
            process_ids.as_mut_ptr(),
            size_of_val(&process_ids) as u32,
            &mut bytes_needed,
        ) == FALSE
        {
            return None;
        }

        let num_processes = bytes_needed / size_of::<DWORD>() as u32;

        for i in 0..num_processes {
            let pid = process_ids[i as usize];
            let process_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
            if process_handle.is_null() {
                continue;
            }

            let mut module_name = [0u16; MAX_PATH];
            let len = GetModuleFileNameExW(
                process_handle,
                null_mut(),
                module_name.as_mut_ptr(),
                MAX_PATH as u32,
            );

            if len > 0 {
                let name = String::from_utf16_lossy(&module_name);
                if name.contains(process_name) {
                    CloseHandle(process_handle);
                    return Some(pid);
                }
            }

            CloseHandle(process_handle);
        }
    }
    None
}

/* Example usage:
let process = Process::new(PID);
let base_address = match get_base_address(PID, process_name) {
    Some(base_address) => base_address,
    None => {
        println!("Module not found");
        return;
    }
};
println!("Base address of module {}: {:#x}", process_name, base_address as usize);
 */
pub fn get_process_base(pid: u32, module_name: &str) -> Option<HMODULE> {
    unsafe {
        let process_handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if process_handle.is_null() {
            eprintln!("Failed to open process with PID {}", pid);
            return None;
        }

        let mut modules: [HMODULE; 1024] = [null_mut(); 1024];
        let mut bytes_needed: DWORD = 0;

        if winapi::um::psapi::EnumProcessModules(
            process_handle,
            modules.as_mut_ptr(),
            size_of_val(&modules) as DWORD,
            &mut bytes_needed,
        ) == FALSE
        {
            CloseHandle(process_handle);
            return None;
        }

        let num_modules = (bytes_needed / size_of::<HMODULE>() as DWORD) as usize;

        for i in 0..num_modules {
            let module_handle = modules[i];
            let mut module_file_name = [0u16; MAX_PATH];
            let len = GetModuleFileNameExW(
                process_handle,
                module_handle,
                module_file_name.as_mut_ptr(),
                MAX_PATH as DWORD,
            );

            if len > 0 {
                let name = String::from_utf16_lossy(&module_file_name);
                if name.contains(module_name) {
                    CloseHandle(process_handle);
                    return Some(module_handle);
                }
            }
        }

        CloseHandle(process_handle);
        None
    }
}

/* Example usage:
let process_name: &str = "s2_mp64_ship.exe";
if !is_process_running(process_name) {
    println!("Process not found! : {}", process_name);
    break;
}
 */
pub fn is_process_running(process_name: &str) -> bool {
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snapshot == INVALID_HANDLE_VALUE {
        return false;
    }

    let mut entry: PROCESSENTRY32 = unsafe { std::mem::zeroed() };
    entry.dwSize = size_of::<PROCESSENTRY32>() as u32;

    let c_process_name = CString::new(process_name).unwrap();

    let mut found = false;
    let mut process = unsafe { Process32First(snapshot, &mut entry) };
    while process != FALSE {
        let exe_file = unsafe { CStr::from_ptr(entry.szExeFile.as_ptr()) };
        if exe_file == c_process_name.as_c_str() {
            found = true;
            break;
        }
        process = unsafe { Process32Next(snapshot, &mut entry) };
    }

    unsafe {
        CloseHandle(snapshot);
    }

    found
}

/* Example usage:
let dll: &str = "game_info.dll";
let base_address = module::get_mod_base(PID, dll);
if base_address.is_null() {
    println("Failed to get {} base address!", dll);
}
 */
pub unsafe fn get_module_base(pid: u32, mod_name: &str) -> Option<*mut std::ffi::c_void> {
    // Convert module name to CString
    let c_mod_name = CString::new(mod_name).expect("Failed to create CString");

    // Create a snapshot of the modules in the process
    let h_snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if h_snap.is_null() {
        return None;
    }

    // Initialize MODULE ENTRY32
    let mut mod_entry: MODULEENTRY32 = std::mem::zeroed();
    mod_entry.dwSize = size_of::<MODULEENTRY32>() as _;

    // Iterate over modules
    let mut mod_base = None;
    if Module32First(h_snap, &mut mod_entry) != 0 {
        loop {
            // Compare module name
            let module_name = CStr::from_ptr(mod_entry.szModule.as_ptr() as *const _);
            if module_name == c_mod_name.as_c_str() {
                mod_base = Some(mod_entry.modBaseAddr as *mut _);
                break;
            }

            if Module32Next(h_snap, &mut mod_entry) == 0 {
                break;
            }
        }
    }

    // Clean up
    CloseHandle(h_snap);
    mod_base
}

pub fn terminate_process(pid: u32) -> Result<(), DWORD> {
    unsafe {
        let handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if handle.is_null() {
            return Err(GetLastError());
        }
        let success = winapi::um::processthreadsapi::TerminateProcess(handle, 0);
        CloseHandle(handle);
        if success == 0 {
            Err(GetLastError())
        } else {
            Ok(())
        }
    }
}

/*
match get_process_info(pid) {
    Some((name, memory_usage, handle_count, thread_count)) => {
        println!("Process ID: {}", pid);
        println!("Process Name: {}", name);
        println!("Memory Usage: {} bytes", memory_usage);
        println!("Handle Count: {}", handle_count);
        println!("Thread Count: {}", thread_count);
    }
    None => {
        println!("Failed to retrieve information for PID {}", pid);
    }
}
 */
pub struct ProcessInfo {
    pub name: String,
    pub memory_usage: usize,
    pub handle_count: DWORD,
    pub thread_count: DWORD,
}

pub fn get_process_info(pid: u32) -> Option<ProcessInfo> {
    unsafe {
        let process_handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if process_handle.is_null() {
            return None;
        }

        // Get memory info
        let mut process_info = PROCESS_MEMORY_COUNTERS {
            cb: size_of::<PROCESS_MEMORY_COUNTERS>() as u32,
            PageFaultCount: 0,
            PeakWorkingSetSize: 0,
            WorkingSetSize: 0,
            QuotaPeakPagedPoolUsage: 0,
            QuotaPagedPoolUsage: 0,
            QuotaPeakNonPagedPoolUsage: 0,
            QuotaNonPagedPoolUsage: 0,
            PagefileUsage: 0,
            PeakPagefileUsage: 0,
        };

        if GetProcessMemoryInfo(
            process_handle,
            &mut process_info,
            size_of::<PROCESS_MEMORY_COUNTERS>() as u32,
        ) == 0
        {
            CloseHandle(process_handle);
            return None;
        }

        // Get module name
        let mut module_name = [0u16; MAX_PATH];
        let len = GetModuleFileNameExW(
            process_handle,
            null_mut(),
            module_name.as_mut_ptr(),
            MAX_PATH as u32,
        );
        let process_name = if len > 0 {
            String::from_utf16_lossy(&module_name)
        } else {
            "Unknown".to_string()
        };

        // Get handle count
        let mut handle_count: DWORD = 0;
        if GetProcessHandleCount(process_handle, &mut handle_count) == 0 {
            handle_count = 0;
        }

        // Get thread count
        let mut thread_count: u32 = 0;
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if snapshot != INVALID_HANDLE_VALUE {
            let mut entry: THREADENTRY32 = std::mem::zeroed();
            entry.dwSize = size_of::<THREADENTRY32>() as u32;

            if Thread32First(snapshot, &mut entry) != 0 {
                loop {
                    if entry.th32OwnerProcessID == pid {
                        thread_count += 1;
                    }
                    if Thread32Next(snapshot, &mut entry) == 0 {
                        break;
                    }
                }
            }

            CloseHandle(snapshot);
        }

        CloseHandle(process_handle);

        Some(ProcessInfo {
            name: process_name,
            memory_usage: process_info.WorkingSetSize as usize,
            handle_count,
            thread_count,
        })
    }
}

/*
let process_ids = list_processes();
for pid in process_ids {
    println!("Process ID: {}", pid);
}
 */
pub fn list_processes() -> Vec<u32> {
    unsafe {
        let mut process_ids: [DWORD; 1024] = [0; 1024];
        let mut bytes_needed: DWORD = 0;

        if EnumProcesses(
            process_ids.as_mut_ptr(),
            size_of_val(&process_ids) as u32,
            &mut bytes_needed,
        ) == FALSE
        {
            return Vec::new();
        }

        let num_processes = bytes_needed / size_of::<DWORD>() as u32;
        process_ids[..num_processes as usize].to_vec()
    }
}

/*
let modules = list_modules(pid);
for module in modules {
    println!("Loaded Module: {}", module);
}
 */
pub fn list_modules(pid: u32) -> Vec<String> {
    unsafe {
        let process_handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if process_handle.is_null() {
            return Vec::new();
        }

        let mut modules: [HMODULE; 1024] = [null_mut(); 1024];
        let mut bytes_needed: DWORD = 0;

        if winapi::um::psapi::EnumProcessModules(
            process_handle,
            modules.as_mut_ptr(),
            size_of_val(&modules) as DWORD,
            &mut bytes_needed,
        ) == FALSE
        {
            CloseHandle(process_handle);
            return Vec::new();
        }

        let num_modules = (bytes_needed / size_of::<HMODULE>() as DWORD) as usize;
        let mut module_names = Vec::new();

        for i in 0..num_modules {
            let mut module_file_name = [0u16; MAX_PATH];
            let len = GetModuleFileNameExW(
                process_handle,
                modules[i],
                module_file_name.as_mut_ptr(),
                MAX_PATH as DWORD,
            );
            if len > 0 {
                let name = String::from_utf16_lossy(&module_file_name);
                module_names.push(name);
            }
        }

        CloseHandle(process_handle);
        module_names
    }
}
