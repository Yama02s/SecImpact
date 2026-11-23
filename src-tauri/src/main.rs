// Evita que se abra una consola negra extra en Windows en modo release
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    secimpact_lib::run()
}
