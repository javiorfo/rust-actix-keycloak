use actix_web::{get, web, App, Error, HttpRequest, HttpResponse, HttpServer, Responder};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use reqwest::Client;
use std::sync::Arc;
use std::collections::HashMap;

#[derive(Deserialize)]
struct KeycloakConfig {
    issuer: String,
//     client_id: String,
    required_role: String, // The required role for access
}

#[derive(Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
    resource_access: HashMap<String, ResourceAccess>, // Add this field to map Keycloak resource access
    // Add other fields you expect in your token
}

#[derive(Deserialize)]
struct ResourceAccess {
    roles: Vec<String>,
}

async fn fetch_jwks(issuer: &str) -> Result<HashMap<String, DecodingKey>, Box<dyn std::error::Error>> {
    let url = format!("{}/protocol/openid-connect/certs", issuer);
    let jwks: serde_json::Value = Client::new()
        .get(&url)
        .send()
        .await?
        .json()
        .await?;
    
    let keys = jwks["keys"].as_array().ok_or_else(|| {
        actix_web::error::ErrorUnauthorized("Invalid JWKS format")
    })?;

    let mut decoding_keys = HashMap::new();
    for key in keys {
        if let (Some(kid), Some(n), Some(e)) = (
            key["kid"].as_str(),
            key["n"].as_str(),
            key["e"].as_str(),
        ) {
            let decoding_key = DecodingKey::from_rsa_components(n, e)
                .map_err(|_| actix_web::error::ErrorUnauthorized("Invalid key format"))?;
            decoding_keys.insert(kid.to_string(), decoding_key);
        }
    }
    Ok(decoding_keys)
}

async fn validate_token(token: &str, config: &KeycloakConfig, decoding_keys: &HashMap<String, DecodingKey>) -> Result<Claims, Error> {
    let header = decode_header(token).map_err(|_| actix_web::error::ErrorUnauthorized("Invalid token"))?;
    let kid = header.kid.ok_or_else(|| actix_web::error::ErrorUnauthorized("Missing kid in token"))?;

    let decoding_key = decoding_keys.get(&kid).ok_or_else(|| actix_web::error::ErrorUnauthorized("Invalid kid"))?;
    
    let mut validation = Validation::new(Algorithm::RS256);
//     validation.set_audience(&[&config.audience]);
    validation.set_issuer(&[&config.issuer]);
    
    let token_data = decode::<Claims>(token, decoding_key, &validation)
        .map_err(|err| actix_web::error::ErrorUnauthorized(err.to_string()))?;
    
    Ok(token_data.claims)
}

async fn check_role(claims: &Claims, required_role: &str) -> bool {
    if let Some(resource_access) = claims.resource_access.get("srv-client") {
        if resource_access.roles.contains(&required_role.to_string()) {
            return true;
        }
    }
    false
}

async fn index(req: HttpRequest) -> impl Responder {
    let config = req.app_data::<Arc<KeycloakConfig>>().unwrap();
    let decoding_keys = req.app_data::<Arc<HashMap<String, DecodingKey>>>().unwrap();

    if let Some(auth_header) = req.headers().get("Authorization") {
        if let Ok(auth_str) = auth_header.to_str() {
            if auth_str.starts_with("Bearer ") {
                let token = &auth_str[7..];
                match validate_token(token, config, decoding_keys).await {
                    Ok(claims) => {
                        if check_role(&claims, &config.required_role).await {
                            return HttpResponse::Ok().body("Hello, you are authenticated and have the required role!");
                        } else {
                            return HttpResponse::Forbidden().body("Forbidden: You do not have the required role");
                        }
                    }
                    Err(err) => {
                        return HttpResponse::Unauthorized().body(err.to_string());
                    }
                }
            }
        }
    }
    HttpResponse::Unauthorized().body("Unauthorized")
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Load Keycloak configuration
    let config = Arc::new(KeycloakConfig {
        issuer: "http://localhost:8081/realms/chaosystema".into(),
//         client_id: "java-spring3-microservice".into(),
        required_role: "CLIENT_ADMIN".into(),
    });

    // Fetch JWKS
    let decoding_keys = Arc::new(fetch_jwks(&config.issuer).await.unwrap());

    HttpServer::new(move || {
        App::new()
            .app_data(config.clone())
            .app_data(decoding_keys.clone())
            .service(greet)
//             .route("/orfosys/dummy", web::get().to(index))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}


#[get("/hello/{name}")]
async fn greet(name: web::Path<String>, req: HttpRequest) -> impl Responder {
    let config = req.app_data::<Arc<KeycloakConfig>>().unwrap();
    let decoding_keys = req.app_data::<Arc<HashMap<String, DecodingKey>>>().unwrap();

    if let Some(auth_header) = req.headers().get("Authorization") {
        if let Ok(auth_str) = auth_header.to_str() {
            if auth_str.starts_with("Bearer ") {
                let token = &auth_str[7..];
                match validate_token(token, config, decoding_keys).await {
                    Ok(claims) => {
                        if check_role(&claims, &config.required_role).await {
                            return HttpResponse::Ok().body(format!("Hello, {}! You are authenticated and have the required role!", name));
                        } else {
                            return HttpResponse::Forbidden().body("Forbidden: You do not have the required role");
                        }
                    }
                    Err(err) => {
                        // Debug: Print the error
                        println!("Token validation error: {:?}", err);
                        return HttpResponse::Unauthorized().body("Invalid token");
                    }
                }
            }
        }
    }
    HttpResponse::Unauthorized().body("Unauthorized")
}

