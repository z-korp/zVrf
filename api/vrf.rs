use z_vrf::curve::*;
use z_vrf::ecvrf::*;

pub type StarkVRF = ECVRF<StarkCurve, z_vrf::hash::PoseidonHash>;

use ark_ec::{short_weierstrass::SWCurveConfig, CurveGroup};
use ark_ff::BigInteger256;
use serde::Serialize;
use serde_json::json;
use std::env;
use std::sync::atomic::{AtomicUsize, Ordering};
use vercel_runtime::{run, Body, Error, Request, Response, StatusCode};

static SEED_COUNTER: AtomicUsize = AtomicUsize::new(42); // Static atomic counter

#[derive(Serialize)]
struct VrfResponse {
    public_key: String,
    seed: String,
    proof_gamma_x: String,
    proof_gamma_y: String,
    proof_c: String,
    proof_s: String,
    proof_verify_hint: String,
    beta: String,
}

pub async fn handler(_req: Request) -> Result<Response<Body>, Error> {
    dotenv::dotenv().ok();

    let secret_key_value = env::var("SECRET_KEY").expect("SECRET_KEY must be set");
    let secret_key = ScalarField::from(secret_key_value.parse::<u64>().unwrap());

    let public_key = (StarkCurve::GENERATOR * secret_key).into_affine();

    // Increment the seed
    let seed_value = SEED_COUNTER.fetch_add(1, Ordering::SeqCst) as u64;
    let seed_bigint = BigInteger256::from(seed_value);
    let seed = BaseField::new(seed_bigint);

    let ecvrf = StarkVRF::new(public_key).unwrap();
    let proof = ecvrf.prove(&secret_key, &[seed]).unwrap();
    let sqrt_ratio_hint = ecvrf.hash_to_sqrt_ratio_hint(&[seed]);
    let beta = ecvrf.proof_to_hash(&proof).unwrap();

    let response = VrfResponse {
        public_key: format!("{:?}", public_key),
        seed: seed_value.to_string(),
        proof_gamma_x: format!("{}", proof.0.x),
        proof_gamma_y: format!("{}", proof.0.y),
        proof_c: format!("{}", proof.1),
        proof_s: format!("{}", proof.2),
        proof_verify_hint: format!("{}", sqrt_ratio_hint),
        beta: format!("{}", beta),
    };

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/json")
        .header("Access-Control-Allow-Origin", "*")
        .header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        .header("Access-Control-Allow-Headers", "Content-Type")
        .body(json!(response).to_string().into())?)
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    run(handler).await
}
