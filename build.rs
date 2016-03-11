extern crate bindgen;

fn build_ffi() {

    let mut builder = bindgen::builder();

    if let Some(clang_include_dir) = bindgen::get_include_dir() {
        builder.clang_arg("-I");
        builder.clang_arg(clang_include_dir);
    }

    let bindings = builder
        .header("extra/gen.h")
        .link("ldap")
        .emit_builtins()
        .generate()
        .expect("Could not generate bindings");

    bindings
        .write_to_file("src/ffi.rs")
        .expect("Could not write bindings to file");
}

fn main() {
    if !::std::fs::metadata("src/ffi.rs").is_ok() { 
        build_ffi();
    }
}