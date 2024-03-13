use std::sync::Arc;

use rocket::http::Status;
use rocket::outcome::Outcome;
use rocket::request::FromRequest;
use rocket::response::status::Conflict;
use rocket::response::Redirect;
use rocket::serde::json::Json;
use rocket::serde::Deserialize;
use rocket::{request, Request, Route, State};

use crate::service::auth_service::AuthTokens;
use crate::service::oauth_service::User;
use crate::service::{auth_service, jwt_service};
use crate::ApiState;

pub fn routes() -> Vec<Route> {
    routes![login, logout, user, refresh]
}

#[post("/logout")]
fn logout() -> Redirect {
    Redirect::to("/")
}

#[post("/login", format = "json", data = "<dto>")]
async fn login(
    dto: Json<LoginDto<'_>>,
    state: &State<ApiState>,
) -> Result<Json<AuthTokens>, Conflict<String>> {
    let tokens = auth_service::login(dto.login, dto.password, Arc::clone(&state.http_client)).await;
    match tokens {
        Ok(tokens) => Ok(Json(tokens)),
        Err(e) => Err(Conflict(e.to_string())),
    }
}

#[post("/refresh", format = "json", data = "<tokens>")]
async fn refresh(
    tokens: Json<AuthTokens>,
    state: &State<ApiState>,
) -> Result<Json<AuthTokens>, Conflict<String>> {
    let tokens = auth_service::refresh(tokens.0, Arc::clone(&state.http_client)).await;
    match tokens {
        Ok(tokens) => Ok(Json(tokens)),
        Err(e) => Err(Conflict(e.to_string())),
    }
}

#[get("/user")]
async fn user(user_guard: UserGuard) -> Json<User> {
    Json(user_guard.0)
}

#[derive(Deserialize, Debug)]
struct LoginDto<'r> {
    login: &'r str,
    password: &'r str,
}

struct UserGuard(User);

#[derive(Debug)]
enum ApiTokenError {
    Missing,
    Invalid,
}

#[async_trait]
impl<'r> FromRequest<'r> for UserGuard {
    type Error = ApiTokenError;

    async fn from_request(request: &'r Request<'_>) -> request::Outcome<Self, Self::Error> {
        let header = request.headers().get_one("Authorization");
        if let Some(header) = header {
            if let Ok(token) = jwt_service::get_token_from_header(header) {
                let user = auth_service::get_user(token).await;
                if let Ok(user) = user {
                    return Outcome::Success(UserGuard(user));
                }
            };
        }

        Outcome::Error((Status::Unauthorized, ApiTokenError::Missing))
    }
}
