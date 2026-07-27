#![allow(missing_docs)]

wit_bindgen::generate!({
    path: "wit",
    world: "imports",
    generate_all,
    pub_export_macro: false,
});
