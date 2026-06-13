// crates/cli/src/recovery.rs
// Social recovery system using Shamir Secret Sharing (W6/G3).
//
// Split a publisher/validator private key into N shares with a threshold
// of M.  Guardians store one share each.  If the key is lost, any M
// guardians can cooperate to reconstruct the key.
//
// Security: shares are individually meaningless.  Only the combination of
// M or more shares reveals the private key.

use anyhow::{bail, Context, Result};
use rand::RngCore;
use std::path::Path;

/// A single Shamir share: (x-coordinate, y-values for each secret byte).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Share {
    /// 1-based share index (the x-coordinate).
    pub index: u8,
    /// Guardian label (e.g. "alice", "bob").
    pub guardian: String,
    /// Hex-encoded share bytes — same length as the secret.
    pub data: String,
    /// Total number of shares (N).
    pub total: u8,
    /// Threshold required to reconstruct (M).
    pub threshold: u8,
}

/// Split a hex-encoded private key into `n` shares with threshold `m`.
///
/// Uses GF(256) Shamir Secret Sharing: each byte of the secret is
/// independently split into shares using a random polynomial of degree
/// `m - 1` evaluated at x = 1..n.
pub fn split(privkey_hex: &str, guardians: &[String], threshold: u8) -> Result<Vec<Share>> {
    let secret =
        hex::decode(privkey_hex.trim()).context("Invalid private key hex for splitting")?;
    let n = u8::try_from(guardians.len()).context("Max 255 guardians supported")?;

    if threshold < 2 {
        bail!("Threshold must be at least 2");
    }
    if threshold > n {
        bail!(
            "Threshold ({}) cannot exceed number of guardians ({})",
            threshold,
            n
        );
    }

    let mut shares: Vec<Vec<u8>> = (0..n).map(|_| Vec::with_capacity(secret.len())).collect();

    let mut rng = rand::rngs::OsRng;

    for &byte in &secret {
        // Build a random polynomial: coeff[0] = byte (the secret), coeff[1..m-1] = random
        let mut coeffs = vec![byte];
        for _ in 1..threshold {
            let mut r = [0u8; 1];
            rng.fill_bytes(&mut r);
            coeffs.push(r[0]);
        }

        // Evaluate polynomial at x = 1..n in GF(256)
        for i in 0..n {
            let x = i + 1; // x = 1, 2, ..., n
            let y = eval_poly_gf256(&coeffs, x);
            shares[i as usize].push(y);
        }
    }

    let result: Vec<Share> = guardians
        .iter()
        .enumerate()
        .map(|(i, name)| Share {
            index: (i + 1) as u8,
            guardian: name.clone(),
            data: hex::encode(&shares[i]),
            total: n,
            threshold,
        })
        .collect();

    Ok(result)
}

/// Reconstruct the private key from `m` or more shares using Lagrange interpolation
/// in GF(256).
pub fn reconstruct(shares: &[Share]) -> Result<String> {
    if shares.is_empty() {
        bail!("No shares provided");
    }
    let threshold = shares[0].threshold;
    if shares.len() < threshold as usize {
        bail!(
            "Need at least {} shares to reconstruct, got {}",
            threshold,
            shares.len()
        );
    }

    let share_data: Vec<(u8, Vec<u8>)> = shares
        .iter()
        .map(|s| {
            let data = hex::decode(&s.data).context("Invalid share hex")?;
            Ok((s.index, data))
        })
        .collect::<Result<Vec<_>>>()?;

    let secret_len = share_data[0].1.len();
    let mut secret = Vec::with_capacity(secret_len);

    for byte_idx in 0..secret_len {
        // Collect (x, y) pairs for this byte position
        let points: Vec<(u8, u8)> = share_data
            .iter()
            .take(threshold as usize)
            .map(|(x, data)| (*x, data[byte_idx]))
            .collect();

        let reconstructed = lagrange_interpolate_gf256(&points, 0);
        secret.push(reconstructed);
    }

    Ok(hex::encode(secret))
}

// ── GF(256) arithmetic ──────────────────────────────────────────────────────

/// Multiplication in GF(256) using the AES irreducible polynomial x^8 + x^4 + x^3 + x + 1.
fn gf256_mul(mut a: u8, mut b: u8) -> u8 {
    let mut result: u8 = 0;
    for _ in 0..8 {
        if b & 1 != 0 {
            result ^= a;
        }
        let carry = a & 0x80;
        a <<= 1;
        if carry != 0 {
            a ^= 0x1B; // AES reduction polynomial
        }
        b >>= 1;
    }
    result
}

/// Multiplicative inverse in GF(256).  Returns 0 for input 0.
fn gf256_inv(a: u8) -> u8 {
    if a == 0 {
        return 0;
    }
    // Exponentiation: a^254 = a^(-1) in GF(256) (since order of group is 255)
    let mut result = a;
    for _ in 0..6 {
        result = gf256_mul(result, result);
        result = gf256_mul(result, a);
    }
    result = gf256_mul(result, result);
    result
}

/// Evaluate a polynomial with coefficients `coeffs` at point `x` in GF(256).
fn eval_poly_gf256(coeffs: &[u8], x: u8) -> u8 {
    let mut result: u8 = 0;
    let mut power: u8 = 1;
    for &coeff in coeffs {
        result ^= gf256_mul(coeff, power);
        power = gf256_mul(power, x);
    }
    result
}

/// Lagrange interpolation at point `x` given a set of (x_i, y_i) pairs in GF(256).
fn lagrange_interpolate_gf256(points: &[(u8, u8)], x: u8) -> u8 {
    let mut result: u8 = 0;
    let k = points.len();

    for i in 0..k {
        let (xi, yi) = points[i];
        let mut numerator: u8 = 1;
        let mut denominator: u8 = 1;

        for j in 0..k {
            if i == j {
                continue;
            }
            let (xj, _) = points[j];
            numerator = gf256_mul(numerator, x ^ xj);
            denominator = gf256_mul(denominator, xi ^ xj);
        }

        let basis = gf256_mul(numerator, gf256_inv(denominator));
        result ^= gf256_mul(yi, basis);
    }

    result
}

// ────────────────────────────────────────────────────────────────────────────
// CLI entry points
// ────────────────────────────────────────────────────────────────────────────

/// `creg recovery split` — split a private key into guardian shares.
pub fn run_split(
    key_path: &Path,
    guardians: &[String],
    threshold: u8,
    output_dir: &Path,
) -> Result<()> {
    use crate::keygen;
    use colored::Colorize;

    // Read and possibly decrypt the private key
    let privkey_hex = if key_path.exists() {
        let content = std::fs::read_to_string(key_path)
            .with_context(|| format!("Cannot read key file: {}", key_path.display()))?;
        if content.starts_with("CREG-ENC-V1") {
            let pw = dialoguer::Password::new()
                .with_prompt("Enter passphrase to decrypt the key")
                .interact()
                .context("passphrase input")?;
            keygen::decrypt_key_file(key_path, &pw)?
        } else {
            content.trim().to_string()
        }
    } else {
        bail!("Key file not found: {}", key_path.display());
    };

    let shares = split(&privkey_hex, guardians, threshold)?;

    // Write each share to a separate file
    std::fs::create_dir_all(output_dir)
        .with_context(|| format!("Cannot create output dir: {}", output_dir.display()))?;

    for share in &shares {
        let filename = format!("share-{}-{}.json", share.index, share.guardian);
        let path = output_dir.join(&filename);
        let json = serde_json::to_string_pretty(share).context("Failed to serialize share")?;
        std::fs::write(&path, &json)
            .with_context(|| format!("Cannot write share to {}", path.display()))?;
        println!(
            "  {} Share #{} for \"{}\" → {}",
            "✓".green(),
            share.index,
            share.guardian,
            path.display()
        );
    }

    println!();
    println!(
        "  {} Split into {} shares (threshold: {} of {})",
        "✓".green(),
        shares.len(),
        threshold,
        shares.len()
    );
    println!("  Distribute each share to the corresponding guardian.");
    println!(
        "  Any {} guardians can reconstruct the key with `creg recovery reconstruct`.",
        threshold
    );

    Ok(())
}

/// `creg recovery reconstruct` — reconstruct a private key from guardian shares.
pub fn run_reconstruct(share_files: &[std::path::PathBuf], output_path: &Path) -> Result<()> {
    use colored::Colorize;

    let mut shares = Vec::new();
    for path in share_files {
        let json = std::fs::read_to_string(path)
            .with_context(|| format!("Cannot read share file: {}", path.display()))?;
        let share: Share = serde_json::from_str(&json)
            .with_context(|| format!("Invalid share JSON in {}", path.display()))?;
        println!(
            "  Loaded share #{} from \"{}\"",
            share.index, share.guardian
        );
        shares.push(share);
    }

    let privkey_hex = reconstruct(&shares)?;

    // Verify it's a valid Ed25519 key
    let key_bytes = hex::decode(&privkey_hex).context("Reconstructed key is not valid hex")?;
    if key_bytes.len() != 32 {
        bail!(
            "Reconstructed key is {} bytes, expected 32",
            key_bytes.len()
        );
    }

    use ed25519_dalek::SigningKey;
    let signing_key = SigningKey::try_from(key_bytes.as_slice())
        .context("Reconstructed key is not a valid Ed25519 key")?;
    let pubkey_hex = hex::encode(signing_key.verifying_key().as_bytes());

    // Prompt for encryption before saving
    let passphrase = dialoguer::Password::new()
        .with_prompt("Enter passphrase to encrypt the recovered key (empty for no encryption)")
        .allow_empty_password(true)
        .with_confirmation("Confirm passphrase", "Passphrases do not match")
        .interact()
        .context("Failed to read passphrase")?;

    if let Some(parent) = output_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    if passphrase.is_empty() {
        std::fs::write(output_path, &privkey_hex)?;
    } else {
        let encrypted = crate::keygen::encrypt_key_pub(&privkey_hex, &passphrase)?;
        std::fs::write(output_path, &encrypted)?;
    }

    println!();
    println!("  {} Key reconstructed successfully!", "✓".green());
    println!("  Public key: {} (Ed25519)", pubkey_hex);
    println!("  Saved to:   {}", output_path.display());

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_and_reconstruct_2_of_3() {
        let secret = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let guardians = vec!["alice".into(), "bob".into(), "carol".into()];
        let shares = split(secret, &guardians, 2).unwrap();
        assert_eq!(shares.len(), 3);

        // Any 2 of 3 should work
        let recovered = reconstruct(&shares[0..2]).unwrap();
        assert_eq!(recovered, secret);

        let recovered2 = reconstruct(&shares[1..3]).unwrap();
        assert_eq!(recovered2, secret);

        let recovered3 = reconstruct(&[shares[0].clone(), shares[2].clone()]).unwrap();
        assert_eq!(recovered3, secret);
    }

    #[test]
    fn test_split_and_reconstruct_3_of_5() {
        let secret = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let guardians: Vec<String> = (1..=5).map(|i| format!("guardian-{}", i)).collect();
        let shares = split(secret, &guardians, 3).unwrap();
        assert_eq!(shares.len(), 5);

        let recovered = reconstruct(&shares[0..3]).unwrap();
        assert_eq!(recovered, secret);

        let recovered2 = reconstruct(&shares[2..5]).unwrap();
        assert_eq!(recovered2, secret);
    }

    #[test]
    fn test_insufficient_shares_fails() {
        let secret = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let guardians = vec!["a".into(), "b".into(), "c".into()];
        let shares = split(secret, &guardians, 3).unwrap();

        let result = reconstruct(&shares[0..2]);
        assert!(
            result.is_err() || {
                let r = result.unwrap();
                r != secret // With fewer shares than threshold, result should differ
            }
        );
    }

    #[test]
    fn test_gf256_arithmetic() {
        assert_eq!(gf256_mul(0, 0), 0);
        assert_eq!(gf256_mul(1, 1), 1);
        assert_eq!(gf256_mul(0, 255), 0);
        // Inverse: a * a^(-1) = 1
        for a in 1..=255u8 {
            let inv = gf256_inv(a);
            assert_eq!(gf256_mul(a, inv), 1, "inverse failed for {}", a);
        }
    }
}
