#[macro_use]
extern crate rocket;

use std::sync::Arc;

use controller::auth_controller;
use controller::main_controller;

mod config;
mod controller;
mod service;

struct ApiState {
    http_client: Arc<reqwest::Client>,
}

#[launch]
fn rocket() -> _ {
    rocket::build()
        .configure(rocket::Config::figment().merge(("port", config::config().SERVER.PORT)))
        .manage(ApiState {
            http_client: Arc::new(reqwest::Client::new()),
        })
        .mount("/api/auth", auth_controller::routes())
        .mount("/", main_controller::routes())
        
}
