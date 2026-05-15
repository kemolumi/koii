use webauthn_rs::{
    Webauthn,
    WebauthnBuilder,
    prelude::{
        AuthenticationResult,
        CreationChallengeResponse,
        Passkey,
        PasskeyAuthentication,
        PasskeyRegistration,
        PublicKeyCredential,
        RegisterPublicKeyCredential,
        RequestChallengeResponse,
        Uuid,
        WebauthnError,
    },
};

use crate::env::ORIGIN_DOMAIN;

pub struct PasskeyService {
    webauthn: Webauthn,
}

impl PasskeyService {
    pub fn new() -> Self {
        let origin = &ORIGIN_DOMAIN;
        let builder = WebauthnBuilder::new(origin.domain().unwrap(), origin).expect(
            "Failed to initialize webauthn."
        );

        PasskeyService {
            webauthn: builder.build().expect("Failed to initialize webauthn."),
        }
    }

    pub async fn register(
        &self,
        name: String
    ) -> Result<(CreationChallengeResponse, PasskeyRegistration), WebauthnError> {
        let gid = nanoid::rngs::default(16);
        let passkey_id: [u8; 16] = *gid.as_array().unwrap();

        self.webauthn.start_passkey_registration(Uuid::from_bytes(passkey_id), &name, &name, None)
    }

    pub async fn complete_register(
        &self,
        registration: &RegisterPublicKeyCredential,
        state: &PasskeyRegistration
    ) -> Result<Passkey, WebauthnError> {
        self.webauthn.finish_passkey_registration(registration, state)
    }

    pub async fn authorize(
        &self,
        passkey: Passkey
    ) -> Result<(RequestChallengeResponse, PasskeyAuthentication), WebauthnError> {
        self.webauthn.start_passkey_authentication(&[passkey])
    }

    pub async fn complete_authorize(
        &self,
        response: &PublicKeyCredential,
        state: &PasskeyAuthentication
    ) -> Result<AuthenticationResult, WebauthnError> {
        self.webauthn.finish_passkey_authentication(response, state)
    }
}
