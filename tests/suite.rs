use axum_test::{ TestResponse, TestServer };
use koii::app;
use serde::{ Deserialize, Serialize };
use serde_json::json;
use reqwest::StatusCode;
use totp_rs::TOTP;

#[tokio::test]
async fn test_suite() {
    koii::init();
    let mut server = axum_test::TestServer::new(app(true).await);

    let correct_password = "a0*0h0*G)8g0dc08hcd";
    let wrong_password = "sd08h800)(H)9h0sdc";

    // No account.
    let response = account_login(&server, correct_password, None).await;
    response.assert_status(StatusCode::NOT_FOUND);
    response.assert_json(&json!({"success": false, "error": "Wrong email or password."}));

    // Sign up.
    let response = create_account(&server, correct_password).await;
    response.assert_status(StatusCode::CREATED);
    response.assert_json(
        &json!({"success": true, "result": "Check your inbox to verify your email!"})
    );

    // Sign up again.
    let response = create_account(&server, correct_password).await;
    response.assert_status(StatusCode::CONFLICT);
    response.assert_json(&json!({"success": false, "error": "Email already registered."}));

    // Sign in bad password.
    let response = account_login(&server, wrong_password, None).await;
    response.assert_status(StatusCode::NOT_FOUND);
    response.assert_json(&json!({"success": false, "error": "Wrong email or password."}));

    // Sign in but didn't verify.
    let response = account_login(&server, correct_password, None).await;
    response.assert_status(StatusCode::FORBIDDEN);
    response.assert_json(
        &json!({"success": false, "error": "This account is pending for verification, please check your email."})
    );

    // Verify account.
    let response = verify_account(&server).await;
    response.assert_status(StatusCode::OK);
    response.assert_json(&json!({"success": true}));

    // Verify again.
    let response = verify_account(&server).await;
    response.assert_status(StatusCode::NOT_FOUND);
    response.assert_json(
        &json!({"success": false, "error": "There's no account associated to this verify token."})
    );

    // Sign in.
    let response = account_login(&server, correct_password, None).await;
    response.assert_status(StatusCode::OK);
    response.assert_json(&json!({"success": true}));

    server.add_cookie(response.cookie("token"));

    // Sign in again.
    let response = account_login(&server, correct_password, None).await;
    response.assert_status(StatusCode::FORBIDDEN);
    response.assert_json(&json!({"success": false, "error": "There's already an active account."}));

    // Sudo methos WITH NO totp setup.
    let response = sudo_methods(&server).await;
    response.assert_status(StatusCode::OK);
    response.assert_json(
        &json!({"success": true, "result": { "email": true, "totp": false, "passkey": false }})
    );

    // Create TOTP.
    let response = setup_totp(&server).await;
    #[derive(Serialize, Deserialize)]
    struct TotpResponse {
        success: bool,
        result: String,
    }
    response.assert_status(StatusCode::CREATED);
    response.assert_json(&json!({"success": true, "result": axum_test::expect_json::string()}));

    let totp = TOTP::from_url(response.json::<TotpResponse>().result).unwrap();

    // Create TOTP again.
    let response = setup_totp(&server).await;
    response.assert_status(StatusCode::FORBIDDEN);
    response.assert_json(
        &json!({"success": false, "error": "There is an exisiting TOTP. Please delete it first."})
    );

    // Sudo methos WITH totp setup.
    let response = sudo_methods(&server).await;
    response.assert_status(StatusCode::OK);
    response.assert_json(
        &json!({"success": true, "result": { "email": false, "totp": true, "passkey": false }})
    );

    // Logout account.
    let response = logout_account(&server).await;
    response.assert_status(StatusCode::OK);
    response.assert_json(&json!({"success": true}));

    // Sudo methods but token is used for logout.
    let response = sudo_methods(&server).await;
    response.assert_status(StatusCode::UNAUTHORIZED);
    response.assert_json(&json!({"success": false, "error": "Get out."}));

    server.clear_cookies();

    // Sign in but miassing TOTP.
    let response = account_login(&server, correct_password, None).await;
    response.assert_status(StatusCode::FORBIDDEN);
    response.assert_json(&json!({"success": false, "error": "TOTP Required."}));

    // Sign in with TOTP.
    let success_login = account_login(
        &server,
        correct_password,
        Some(totp.generate_current().unwrap())
    ).await;
    success_login.assert_status(StatusCode::OK);
    success_login.assert_json(&json!({"success": true}));

    // Sign in with the same TOTP code.
    let response = account_login(
        &server,
        correct_password,
        Some(totp.generate_current().unwrap())
    ).await;
    response.assert_status(StatusCode::UNAUTHORIZED);
    response.assert_json(&json!({"success": false, "error": "Wrong TOTP code."}));

    // Add refresh from previous successful login.
    server.add_cookie(success_login.cookie("refresh"));

    // Refresh token.
    let response = refresh_account(&server).await;
    response.assert_status(StatusCode::OK);
    response.assert_json(&json!({"success": true}));

    // Try refreshing using the revoked refresh.
    let response = refresh_account(&server).await;
    response.assert_status(StatusCode::UNAUTHORIZED);
    response.assert_json(&json!({"success": false, "error": "Get out."}));
}

async fn account_login(server: &TestServer, password: &str, code: Option<String>) -> TestResponse {
    server
        .post("/account/login")
        .json(
            &json!({"email": "test@dafinsdaf.com", "password": password, "totp_code": code, "clientstile": "A"})
        ).await
}

async fn create_account(server: &TestServer, password: &str) -> TestResponse {
    server
        .post("/account")
        .json(
            &json!({"email": "test@dafinsdaf.com", "password": password, "clientstile": "A"})
        ).await
}

async fn verify_account(server: &TestServer) -> TestResponse {
    server.patch("/account/verify").json(&json!({"verify_code": "debug"})).await
}

async fn sudo_methods(server: &TestServer) -> TestResponse {
    server.get("/account/sudo/methods").await
}

async fn setup_totp(server: &TestServer) -> TestResponse {
    server.post("/account/totp").json(&json!({"name": "Hello"})).await
}

async fn refresh_account(server: &TestServer) -> TestResponse {
    server.get("/account/refresh").await
}

async fn logout_account(server: &TestServer) -> TestResponse {
    server.get("/account/logout").await
}
