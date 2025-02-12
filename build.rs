fn main() {
    slint_build::compile("ui/main.slint").unwrap();
    println!("cargo:rerun-if-changed=ui/main.slint");
}