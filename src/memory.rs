extern crate winapi;

use std::mem::size_of;
use std::ptr::null_mut;
use winapi::shared::minwindef::{DWORD, FALSE};
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::handleapi::CloseHandle;
use winapi::um::memoryapi::{ReadProcessMemory, WriteProcessMemory};
use winapi::um::processthreadsapi::OpenProcess;
use winapi::um::winnt::{HANDLE, PROCESS_ALL_ACCESS};

pub struct Process {
    handle: HANDLE,
}

impl Process {
    pub fn new(pid: u32) -> Self {
        unsafe {
            let handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
            if handle.is_null() {
                panic!("Failed to open process with PID {}", pid);
            }
            Process { handle }
        }
    }

    pub fn read_memory<T>(&self, address: usize, buffer: &mut T) -> Result<(), DWORD> {
        unsafe {
            let success = ReadProcessMemory(
                self.handle,
                address as *const _,
                buffer as *mut _ as *mut _,
                size_of::<T>(),
                null_mut(),
            );
            if success == 0 {
                Err(GetLastError())
            } else {
                Ok(())
            }
        }
    }

    pub fn write_memory<T>(&self, address: usize, buffer: &T) -> Result<(), DWORD> {
        unsafe {
            let success = WriteProcessMemory(
                self.handle,
                address as *mut _,
                buffer as *const _ as *const _,
                size_of::<T>(),
                null_mut(),
            );
            if success == 0 {
                Err(GetLastError())
            } else {
                Ok(())
            }
        }
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.handle);
        }
    }
}
