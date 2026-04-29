use sysinfo::System;

pub fn get_os_info() -> Option<String> {
    let _sys = System::new_all();
    System::name()
}
