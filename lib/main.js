import * as core from "@actions/core";
import { Octokit } from "@octokit/core";
import sodium from "libsodium-wrappers";
/**
 * Fetches the public key for the repository's Dependabot secrets
 */
async function getPublicKey(octokit, owner, repo) {
    const response = await octokit.request("GET /repos/{owner}/{repo}/dependabot/secrets/public-key", {
        owner,
        repo,
        headers: {
            "X-GitHub-Api-Version": "2022-11-28",
        },
    });
    return {
        key_id: response.data.key_id,
        key: response.data.key,
    };
}
/**
 * Encrypts a secret value using the provided public key
 */
async function encryptSecret(secretValue, publicKey) {
    // Ensure sodium is ready
    await sodium.ready;
    // Convert the secret and key to Uint8Array
    const messageBytes = sodium.from_string(secretValue);
    const keyBytes = sodium.from_base64(publicKey, sodium.base64_variants.ORIGINAL);
    // Encrypt using libsodium sealed box (compatible with GitHub's encryption)
    const encryptedBytes = sodium.crypto_box_seal(messageBytes, keyBytes);
    // Convert to base64
    return sodium.to_base64(encryptedBytes, sodium.base64_variants.ORIGINAL);
}
/**
 * Updates a Dependabot secret in the repository
 */
async function updateDependabotSecret(octokit, owner, repo, secretName, encryptedValue, keyId) {
    await octokit.request("PUT /repos/{owner}/{repo}/dependabot/secrets/{secret_name}", {
        owner,
        repo,
        secret_name: secretName,
        encrypted_value: encryptedValue,
        key_id: keyId,
        headers: {
            "X-GitHub-Api-Version": "2022-11-28",
        },
    });
}
/**
 * Main function that orchestrates the secret update process
 */
async function run() {
    try {
        // Get inputs from action.yml
        const token = core.getInput("token", { required: true });
        const owner = core.getInput("owner", { required: true });
        const repo = core.getInput("repo", { required: true });
        const secretName = core.getInput("secret_name", { required: true });
        const secretValue = core.getInput("secret_value", { required: true });
        // Initialize Octokit with the provided token
        const octokit = new Octokit({
            auth: token,
        });
        core.info(`Fetching public key for ${owner}/${repo}...`);
        const publicKey = await getPublicKey(octokit, owner, repo);
        core.info(`Encrypting secret value...`);
        const encryptedValue = await encryptSecret(secretValue, publicKey.key);
        core.info(`Updating Dependabot secret '${secretName}'...`);
        await updateDependabotSecret(octokit, owner, repo, secretName, encryptedValue, publicKey.key_id);
        core.info(`✓ Successfully updated Dependabot secret '${secretName}' in ${owner}/${repo}`);
    }
    catch (error) {
        if (error instanceof Error) {
            core.setFailed(error.message);
        }
        else {
            core.setFailed("An unknown error occurred");
        }
    }
}
// Export functions for testing
export { getPublicKey, encryptSecret, updateDependabotSecret, run };
// Run the action if this is the main module
if (import.meta.url === `file://${process.argv[1]}`) {
    run();
}
