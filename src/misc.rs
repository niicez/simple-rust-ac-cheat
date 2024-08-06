use std::io;
use std::process::Command;

pub fn title(title: &str) {
    Command::new("cmd")
        .args(&["/C", format!("title {}", title).as_str()])
        .output()
        .expect("Failed to set console title");
}

pub fn pause() {
    println!("Press Enter to continue...");
    let _ = io::stdin().read_line(&mut String::new());
}

pub fn clear() {
    Command::new("cmd")
        .args(&["/C", "cls"])
        .status()
        .expect("Failed to clear the console");
}

pub fn execute_command(command: &str) -> String {
    let output = Command::new("cmd")
        .args(&["/C", command])
        .output()
        .expect("Failed to execute command");

    String::from_utf8_lossy(&output.stdout).to_string()
}