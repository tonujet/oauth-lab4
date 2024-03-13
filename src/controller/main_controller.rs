use std::path::Path;
use rocket::fs::NamedFile;
use rocket::Route;

pub fn routes() -> Vec<Route> {
    routes![main_page]
}

#[get("/")]
async fn main_page() -> Option<NamedFile> {
    NamedFile::open(Path::new("static/index.html")).await.ok()
}